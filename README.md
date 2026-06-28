# JWT Auth Service

A Spring Boot application focused on implementing JWT authentication and refresh tokens, 
built to explore and better understand spring security mechanisms.

## Application Assumptions
- **Simple security-focused application**  
  Minimal set of endpoints, primarily for login and authorization.

- **JWT with asymmetric or symmetric key and refresh token**  
  Authentication using JWT with a chosen encryption algorithm (asymmetric like RS256 or symmetric like HS256) and refresh tokens for session renewal.

- **Password hashing with salt and pepper**  
  User passwords are hashed using a unique per-user salt and a global pepper, enhancing security of data.

- **PostgreSQL database**  
  User data stored in a `user` table in PostgreSQL.

- **PostgreSQL database in Docker**  
  Database running in a Docker container, configured via a `docker-compose.yml` file.

## How to run
To run this application, needs Docker with PostgreSQL database.

or run with docker compose

```bash
docker-compose up -d --build
```

