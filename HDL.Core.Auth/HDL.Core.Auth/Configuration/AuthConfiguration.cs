using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace HDL.Core.Auth.Configuration
{
    public static class AuthConfiguration
    {
        public static void ConfigureSSO(this IServiceCollection services, IConfiguration configuration, bool IsDevelopment)
        {
           
            var AuthenticationBuilder = services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            });

            AuthenticationBuilder.AddJwtBearer(options =>
            {
                ConfigureValidationParameters(configuration, options);
                ConfigureEvents(IsDevelopment, options);
            });
        }

        private static void ConfigureEvents(bool IsDevelopment, JwtBearerOptions options)
        {
            options.Events = new JwtBearerEvents()
            {
                OnTokenValidated = c =>
                {
                    Console.WriteLine("User successfully authenticated");
                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = c =>
                {
                    c.NoResult();

                    c.Response.StatusCode = 500;
                    c.Response.ContentType = "text/plain";

                    if (IsDevelopment)
                    {
                        return c.Response.WriteAsync(c.Exception.ToString());
                    }
                    return c.Response.WriteAsync("An error occured processing your authentication.");
                }
            };
        }

        private static void ConfigureValidationParameters(IConfiguration configuration, JwtBearerOptions options)
        {
            var issuer = configuration.GetValue<string>("SSO_ISSUER");

            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = true,
                ValidIssuers = new[] { issuer },
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = BuildRSAKey(configuration),
                ValidateLifetime = true
            };
        }

        private static RsaSecurityKey BuildRSAKey(IConfiguration configuration)
        {
            RSA rsa = RSA.Create();

            string publicKey = configuration.GetValue<string>("SSO_PUBLIC_KEY");

            rsa.ImportSubjectPublicKeyInfo(source: Convert.FromBase64String(publicKey), bytesRead: out _);

            var issuerSigningKey = new RsaSecurityKey(rsa);

            return issuerSigningKey;
        }
    }
}
