# VR Backend (Vercel + Flask) - no Meta credentials needed

Endpoints
- `POST /api/auth/login` `{ "CustomId": "<long random id>", "Device": "Quest", "ClientKey": "<optional>" }` -> PlayFab login, returns `SessionToken` + Photon app ids
- `GET/POST /api/photon/auth` - Photon Custom Authentication webhook (`token=<SessionToken>`)
- `POST /api/CORP/Mothership-Auth` - your original endpoint, needs `Authorization: Bearer <SessionToken>`
- `GET /api/health`

Client: generate `Guid.NewGuid().ToString("N")` once, save in PlayerPrefs, send it as CustomId every login.

Deploy: push to GitHub, import in Vercel, add the env vars from `.env.example`, deploy.
Photon: Custom Authentication URL = `https://<project>.vercel.app/api/photon/auth` on both Realtime and Voice apps.
