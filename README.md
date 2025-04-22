# SecureAuth API

A secure authentication API built with ASP.NET Core 8.0 that provides robust user authentication and authorization capabilities using JWT (JSON Web Tokens).

## Project Overview

SecureAuth API is a RESTful authentication service that manages user registration, login, and secure access to protected resources. It implements industry-standard security practices using ASP.NET Core Identity and JWT authentication.

## Technologies Used

- **.NET Version**: .NET 8.0
- **Framework**: ASP.NET Core 8.0

### Packages

- **Microsoft.AspNetCore.Authentication.JwtBearer** (8.0.4): JWT authentication middleware
- **Microsoft.AspNetCore.Identity.EntityFrameworkCore** (8.0.4): ASP.NET Core Identity with Entity Framework Core
- **Microsoft.AspNetCore.OpenApi** (8.0.15): OpenAPI support for ASP.NET Core
- **Microsoft.EntityFrameworkCore** (8.0.4): Core Entity Framework functionality
- **Microsoft.EntityFrameworkCore.SqlServer** (8.0.4): SQL Server database provider for EF Core
- **Microsoft.EntityFrameworkCore.Tools** (8.0.4): EF Core tools for migrations
- **Swashbuckle.AspNetCore** (6.6.2): Swagger tools for API documentation

## Admin Password and Name
```bash
{
  "username": "admin",
  "password": "Admin123!"
}
```


## Installation and Setup Guide

Follow these steps to set up and run the SecureAuth API on your local machine:

### 1. Clone the Repository

```bash
git clone https://github.com/soneryesilay/SecureAuth.git
cd SecureAuth
```

### 2. Configure the Database Connection

Open the `appsettings.json` file in the SecureAuthApi project and update the connection string to point to your SQL Server instance:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=YOUR_SERVER;Database=SecureAuthDb;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=True"
}
```

### 3. Apply Database Migrations

Open a terminal in the SecureAuthApi project directory and run the following commands:

```bash
dotnet ef database update
```

If you need to create a new migration, use:

```bash
dotnet ef migrations add YourMigrationName
dotnet ef database update
```

### 4. Build and Run the Project

```bash
dotnet build
dotnet run
```

The API will be available at:
- API Endpoints: https://localhost:7255 and http://localhost:5062 (ports may vary)
- Swagger UI: https://localhost:7255/swagger (if running in development mode)

## API Features

- User registration and authentication
- JWT token generation and validation
- Secure password handling with ASP.NET Core Identity
- Protected endpoints with role-based authorization

## Medium Blog
https://medium.com/@soneryesilay/10-ad%C4%B1mda-asp-net-core-8-0-ile-jwt-tabanl%C4%B1-kimlik-do%C4%9Frulama-sistemi-olu%C5%9Fturma-65c775614937

## License

This project is licensed with the [MIT License](https://github.com/soneryesilay/SecureAuth/blob/main/LICENSE)
