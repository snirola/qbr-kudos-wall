# QBR Kudos Wall

The existing `kudos-wall.html` frontend now uses an ASP.NET Core API and PostgreSQL instead of Google Forms and Google Apps Script.

## Security model

- Anyone can submit kudos through `POST /api/kudos`.
- Only authenticated administrators can list, update, or delete kudos.
- Admin passwords are stored as ASP.NET Core Identity password hashes.
- Admin sessions expire after eight hours; only SHA-256 token hashes are stored in PostgreSQL.
- Public submissions and login attempts are rate limited by IP address.
- The frontend renders submitted content with `textContent`, avoiding HTML injection.

## Local setup with Docker

1. Copy `.env.example` to `.env`.
2. Replace every placeholder in `.env` with private values. The example bootstrap username is `admin`; use a private password of at least eight characters before exposing the application publicly.
3. Start the API and PostgreSQL:

   ```powershell
   docker compose up --build
   ```

4. Open `C:\Projects\qbr-kudos-wall\kudos-wall.html` in a browser.
5. Submit kudos publicly or select **View Wall** and use the bootstrap administrator credentials from `.env`.

The current hosted version is available at `https://qbr-kudos-wall-git-refactoredkudos-shipra3.vercel.app/`. The page uses a relative API address from its `api-base-url` meta element, so the frontend and API work together on the same deployment.

The bootstrap account is created only when its email does not already exist. Changing the password in `.env` later does not overwrite an existing administrator password.

## Run without Docker (Windows)

Install the .NET 10 SDK and PostgreSQL 17, then create the database and login once from `psql` while connected as a PostgreSQL administrator:

```sql
CREATE USER kudos WITH PASSWORD 'use-the-password-from-your-env-file';
CREATE DATABASE kudos_wall OWNER kudos;
```

Copy `.env.example` to `.env`, replace all placeholders, and start the API:

```powershell
Copy-Item .env.example .env
notepad .env
.\scripts\Start-Local.ps1
```

The launcher checks for the .NET 10 SDK and PostgreSQL, reads `.env` into process-scoped environment variables, and starts the API at `http://localhost:5080`. It does not modify your machine-wide environment. The API creates its initial tables and indexes at startup.

If PostgreSQL uses a non-default host or port, run the API directly with a custom connection string instead:

```powershell
$env:ConnectionStrings__KudosWall = 'Host=server;Port=5432;Database=kudos_wall;Username=kudos;Password=your-password'
$env:BootstrapAdmin__Email = 'admin@example.com'
$env:BootstrapAdmin__Password = 'your-long-admin-password'
dotnet run --project .\KudosWall.Api --launch-profile http
```

## Production configuration

- Host the API and PostgreSQL on an always-on server with persistent storage and backups.
- Terminate HTTPS in front of the API using a reverse proxy such as Caddy or Nginx.
- Change the frontend `api-base-url` meta value to the public HTTPS API address.
- Set `Cors__AllowedOrigins__0` to the deployed frontend origin, for example `https://kudos.example.com`.
- Keep the PostgreSQL connection string and bootstrap password outside source control.
- Remove the bootstrap password from the runtime environment after the first administrator has been created.
- Do not expose PostgreSQL port 5432 publicly.

Vercel detects the root `Dockerfile.vercel` and deploys the static page and ASP.NET API together. PostgreSQL remains an external persistent service and can be attached through a Vercel Marketplace integration such as Neon. Set `ConnectionStrings__KudosWall`, `BootstrapAdmin__Email`, and `BootstrapAdmin__Password` in the production environment before deployment.

## API endpoints

- `GET /api/health`
- `POST /api/kudos`
- `POST /api/admin/login`
- `POST /api/admin/logout`
- `GET /api/admin/kudos`
- `GET /api/admin/storage`
- `GET /api/admin/kudos/export`
- `POST /api/admin/kudos/import`
- `PATCH /api/admin/kudos/{id}/status`
- `DELETE /api/admin/kudos/{id}`

## Submission and storage limits

- Public submissions are limited to 10 requests per IP address every 10 minutes.
- First name and last name accept up to 100 characters each; feedback accepts up to 500 characters.
- There is no application-level maximum number of kudos rows. The deployed database storage allowance is the limiting factor.
- View Wall displays the live record count and database size. It shows a cleanup warning at 80% of the configured 0.5 GB storage allowance; both values can be overridden with `Storage__PlanLimitBytes` and `Storage__WarningPercent`.
