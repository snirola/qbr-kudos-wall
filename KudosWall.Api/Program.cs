using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

var vercelPort = Environment.GetEnvironmentVariable("PORT");
if (!string.IsNullOrWhiteSpace(vercelPort))
    builder.WebHost.UseUrls($"http://0.0.0.0:{vercelPort}");

var connectionString = builder.Configuration.GetConnectionString("KudosWall")
    ?? DatabaseConnection.FromPostgresEnvironment(builder.Configuration)
    ?? throw new InvalidOperationException("ConnectionStrings:KudosWall is required.");

builder.Services.AddSingleton(NpgsqlDataSource.Create(connectionString));
builder.Services.AddSingleton<IPasswordHasher<AdminUser>, PasswordHasher<AdminUser>>();
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
{
    var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? [];
    policy.SetIsOriginAllowed(origin =>
            allowedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase) ||
            (builder.Environment.IsDevelopment() && origin == "null"))
        .AllowAnyHeader()
        .AllowAnyMethod();
}));
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("public-submissions", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(10), QueueLimit = 0 }));
    options.AddPolicy("admin-login", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 5, Window = TimeSpan.FromMinutes(10), QueueLimit = 0 }));
});

var app = builder.Build();
app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseCors();
app.UseRateLimiter();

await Database.InitializeAsync(
    app.Services.GetRequiredService<NpgsqlDataSource>(),
    app.Services.GetRequiredService<IPasswordHasher<AdminUser>>(),
    builder.Configuration);

app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/api/kudos", async (CreateKudosRequest request, NpgsqlDataSource dataSource) =>
{
    var errors = Validation.Validate(request);
    if (errors.Count > 0) return Results.ValidationProblem(errors);

    await using var command = dataSource.CreateCommand("""
        INSERT INTO kudos (recipient_name, message, category, emoji)
        VALUES ($1, $2, $3, $4)
        RETURNING id, submitted_at;
        """);
    command.Parameters.AddWithValue(request.RecipientName.Trim());
    command.Parameters.AddWithValue(request.Message.Trim());
    command.Parameters.AddWithValue(request.Category);
    command.Parameters.AddWithValue(request.Emoji);
    await using var reader = await command.ExecuteReaderAsync();
    await reader.ReadAsync();
    return Results.Created($"/api/kudos/{reader.GetGuid(0)}", new
    {
        id = reader.GetGuid(0),
        submittedAt = reader.GetDateTime(1)
    });
}).RequireRateLimiting("public-submissions");

app.MapPost("/api/admin/login", async (
    AdminLoginRequest request,
    NpgsqlDataSource dataSource,
    IPasswordHasher<AdminUser> passwordHasher) =>
{
    if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
        return Results.Unauthorized();
    var email = request.Email.Trim().ToLowerInvariant();
    await using var command = dataSource.CreateCommand("""
        SELECT id, email, password_hash FROM admin_users
        WHERE email = $1 AND is_active = TRUE;
        """);
    command.Parameters.AddWithValue(email);
    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync()) return Results.Unauthorized();

    var admin = new AdminUser(reader.GetGuid(0), reader.GetString(1), reader.GetString(2));
    if (passwordHasher.VerifyHashedPassword(admin, admin.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
        return Results.Unauthorized();

    await reader.DisposeAsync();
    var token = SessionTokens.Create();
    await using var sessionCommand = dataSource.CreateCommand("""
        INSERT INTO admin_sessions (token_hash, admin_user_id, expires_at)
        VALUES ($1, $2, NOW() + INTERVAL '8 hours');
        """);
    sessionCommand.Parameters.AddWithValue(SessionTokens.Hash(token));
    sessionCommand.Parameters.AddWithValue(admin.Id);
    await sessionCommand.ExecuteNonQueryAsync();
    return Results.Ok(new { token, admin = new { admin.Email }, expiresInSeconds = 28800 });
}).RequireRateLimiting("admin-login");

app.MapPost("/api/admin/logout", async (HttpRequest request, NpgsqlDataSource dataSource) =>
{
    var token = SessionTokens.ReadBearerToken(request);
    if (token is not null)
    {
        await using var command = dataSource.CreateCommand("DELETE FROM admin_sessions WHERE token_hash = $1;");
        command.Parameters.AddWithValue(SessionTokens.Hash(token));
        await command.ExecuteNonQueryAsync();
    }
    return Results.NoContent();
});

app.MapGet("/api/admin/kudos", async (HttpRequest request, NpgsqlDataSource dataSource) =>
{
    if (!await SessionTokens.IsAdminAsync(request, dataSource)) return Results.Unauthorized();

    var results = new List<KudosResponse>();
    await using var command = dataSource.CreateCommand("""
        SELECT id, recipient_name, message, category, emoji, submitted_at, status
        FROM kudos ORDER BY submitted_at DESC;
        """);
    await using var reader = await command.ExecuteReaderAsync();
    while (await reader.ReadAsync())
    {
        results.Add(new KudosResponse(reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
            reader.GetString(3), reader.GetString(4), reader.GetDateTime(5), reader.GetString(6)));
    }
    return Results.Ok(results);
});

app.MapPatch("/api/admin/kudos/{id:guid}/status", async (
    Guid id, UpdateStatusRequest request, HttpRequest httpRequest, NpgsqlDataSource dataSource) =>
{
    if (!await SessionTokens.IsAdminAsync(httpRequest, dataSource)) return Results.Unauthorized();
    if (request.Status is not ("pending" or "approved" or "archived"))
        return Results.ValidationProblem(new Dictionary<string, string[]> { ["status"] = ["Invalid status."] });

    await using var command = dataSource.CreateCommand("UPDATE kudos SET status = $1 WHERE id = $2;");
    command.Parameters.AddWithValue(request.Status);
    command.Parameters.AddWithValue(id);
    return await command.ExecuteNonQueryAsync() == 0 ? Results.NotFound() : Results.NoContent();
});

app.MapDelete("/api/admin/kudos/{id:guid}", async (Guid id, HttpRequest request, NpgsqlDataSource dataSource) =>
{
    if (!await SessionTokens.IsAdminAsync(request, dataSource)) return Results.Unauthorized();
    await using var command = dataSource.CreateCommand("DELETE FROM kudos WHERE id = $1;");
    command.Parameters.AddWithValue(id);
    return await command.ExecuteNonQueryAsync() == 0 ? Results.NotFound() : Results.NoContent();
});

app.Run();

record CreateKudosRequest(string RecipientName, string Message, string Category, string Emoji);
record AdminLoginRequest(string Email, string Password);
record UpdateStatusRequest(string Status);
record AdminUser(Guid Id, string Email, string PasswordHash);
record KudosResponse(Guid Id, string RecipientName, string Message, string Category, string Emoji, DateTime SubmittedAt, string Status);

static class Validation
{
    private static readonly HashSet<string> Categories = ["hero", "save", "team", "brain", "unsung", "easier"];
    private static readonly HashSet<string> Emojis = ["😎", "🚀", "🦸", "🔥", "⭐", "💪"];
    public static Dictionary<string, string[]> Validate(CreateKudosRequest request)
    {
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.RecipientName) || request.RecipientName.Trim().Length > 100)
            errors["recipientName"] = ["Recipient name is required and must not exceed 100 characters."];
        if (string.IsNullOrWhiteSpace(request.Message) || request.Message.Trim().Length > 500)
            errors["message"] = ["Message is required and must not exceed 500 characters."];
        if (!Categories.Contains(request.Category)) errors["category"] = ["Invalid category."];
        if (!Emojis.Contains(request.Emoji)) errors["emoji"] = ["Invalid emoji."];
        return errors;
    }
}

static class SessionTokens
{
    public static string Create() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static byte[] Hash(string token) => SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token));
    public static string? ReadBearerToken(HttpRequest request)
    {
        var value = request.Headers.Authorization.ToString();
        return value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? value[7..].Trim() : null;
    }
    public static async Task<bool> IsAdminAsync(HttpRequest request, NpgsqlDataSource dataSource)
    {
        var token = ReadBearerToken(request);
        if (string.IsNullOrWhiteSpace(token)) return false;
        await using var command = dataSource.CreateCommand("""
            SELECT EXISTS (
                SELECT 1 FROM admin_sessions s
                JOIN admin_users a ON a.id = s.admin_user_id
                WHERE s.token_hash = $1 AND s.expires_at > NOW() AND a.is_active = TRUE
            );
            """);
        command.Parameters.AddWithValue(Hash(token));
        return (bool)(await command.ExecuteScalarAsync() ?? false);
    }
}

static class Database
{
    public static async Task InitializeAsync(NpgsqlDataSource dataSource, IPasswordHasher<AdminUser> hasher, IConfiguration config)
    {
        await using var command = dataSource.CreateCommand("""
            CREATE TABLE IF NOT EXISTS admin_users (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email VARCHAR(320) NOT NULL UNIQUE,
                password_hash TEXT NOT NULL, is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token_hash BYTEA PRIMARY KEY, admin_user_id UUID NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
                expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS ix_admin_sessions_expires_at ON admin_sessions(expires_at);
            CREATE TABLE IF NOT EXISTS kudos (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(), recipient_name VARCHAR(100) NOT NULL,
                message VARCHAR(500) NOT NULL,
                category VARCHAR(20) NOT NULL CHECK (category IN ('hero','save','team','brain','unsung','easier')),
                emoji VARCHAR(10) NOT NULL, submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','archived'))
            );
            CREATE INDEX IF NOT EXISTS ix_kudos_submitted_at ON kudos(submitted_at DESC);
            CREATE INDEX IF NOT EXISTS ix_kudos_status ON kudos(status);
            DELETE FROM admin_sessions WHERE expires_at <= NOW();
            """);
        await command.ExecuteNonQueryAsync();

        var email = config["BootstrapAdmin:Email"]?.Trim().ToLowerInvariant();
        var password = config["BootstrapAdmin:Password"];
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password)) return;
        if (password.Length < 8) throw new InvalidOperationException("Bootstrap admin password must be at least 8 characters.");
        var admin = new AdminUser(Guid.Empty, email, string.Empty);
        await using var bootstrap = dataSource.CreateCommand("""
            INSERT INTO admin_users (email, password_hash) VALUES ($1, $2)
            ON CONFLICT (email) DO NOTHING;
            """);
        bootstrap.Parameters.AddWithValue(email);
        bootstrap.Parameters.AddWithValue(hasher.HashPassword(admin, password));
        await bootstrap.ExecuteNonQueryAsync();
    }
}

static class DatabaseConnection
{
    public static string? FromPostgresEnvironment(IConfiguration config)
    {
        var host = config["PGHOST"];
        var database = config["PGDATABASE"] ?? config["POSTGRES_DATABASE"];
        var username = config["PGUSER"] ?? config["POSTGRES_USER"];
        var password = config["PGPASSWORD"] ?? config["POSTGRES_PASSWORD"];

        if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(database) ||
            string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return null;

        var port = int.TryParse(config["PGPORT"], out var configuredPort) ? configuredPort : 5432;
        return new NpgsqlConnectionStringBuilder
        {
            Host = host,
            Port = port,
            Database = database,
            Username = username,
            Password = password,
            SslMode = SslMode.Require
        }.ConnectionString;
    }
}
