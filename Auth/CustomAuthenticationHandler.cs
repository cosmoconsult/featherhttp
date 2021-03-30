using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace Auth
{
    public class JwtBearerAuthenticationOptions : AuthenticationSchemeOptions
    {

    }

    public class CustomAuthenticationHandler : AuthenticationHandler<JwtBearerAuthenticationOptions>
    {
        private readonly IConfiguration _configuration;
        private readonly string[] DEFAULT_VALID_DOMAINS = new string[] { "cosmoconsult.com", "arssolvendi.onmicrosoft.com" };

        public CustomAuthenticationHandler(
            IOptionsMonitor<JwtBearerAuthenticationOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IConfiguration configuration)
            : base(options, logger, encoder, clock)
        {
            _configuration = configuration;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.Fail("Unauthorized");

            string authorizationHeader = Request.Headers["Authorization"];
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return AuthenticateResult.NoResult();
            }

            if (authorizationHeader.StartsWith("bearer", StringComparison.OrdinalIgnoreCase))
            {
                string token = authorizationHeader.Substring("bearer".Length).Trim();

                if (string.IsNullOrEmpty(token))
                {
                    return AuthenticateResult.Fail("Unauthorized");
                }

                try
                {
                    return await validateToken(token);
                }
                catch (Exception ex)
                {
                    return AuthenticateResult.Fail(ex.Message);
                }
            }
            else
            {
                return AuthenticateResult.Fail("Unauthorized");
            }
        }

        private async Task<AuthenticateResult> validateToken(string token)
        {
            var _configManager = new ConfigurationManager<OpenIdConnectConfiguration>($"https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration", new OpenIdConnectConfigurationRetriever());
            var config = await _configManager.GetConfigurationAsync().ConfigureAwait(false);

            IList<string> validissuers = new List<string>()
            {
                "https://login.microsoftonline.com/{tenantid}/",
                "https://login.microsoftonline.com/{tenantid}/v2.0",
                "https://login.windows.net/{tenantid}/",
                "https://login.microsoft.com/{tenantid}/",
                "https://sts.windows.net/{tenantid}/"
            };

            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidAudiences = new[] { "https://management.core.windows.net/" },
                ValidIssuers = validissuers,
                IssuerSigningKeys = config.SigningKeys,
                IssuerValidator = ValidateIssuerWithPlaceHolder
            };

            SecurityToken securityToken;
            var jwtHandler = new JwtSecurityTokenHandler();
            try
            {
                var claimsPrincipal = jwtHandler.ValidateToken(token, validationParameters, out securityToken);
                if (!validateEmail(claimsPrincipal.Identity.Name))
                    return AuthenticateResult.Fail("request using an invalid domain");

                return AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal, new AuthenticationProperties(), "custom"));
            }
            catch (SecurityTokenValidationException stex)
            {
                return AuthenticateResult.Fail(stex.Message);
            }
        }

        private string ValidateIssuerWithPlaceHolder(string issuer, SecurityToken token, TokenValidationParameters parameters)
        {
            // Accepts any issuer of the form "https://login.microsoftonline.com/{tenantid}/v2.0",
            // where tenantid is the tid from the token.

            if (token is JwtSecurityToken jwt)
            {
                if (jwt.Payload.TryGetValue("tid", out var value) &&
                    value is string tokenTenantId)
                {
                    var allValidIssuers = (parameters.ValidIssuers ?? Enumerable.Empty<string>())
                        .Append(parameters.ValidIssuer)
                        .Where(i => !string.IsNullOrEmpty(i));

                    if (allValidIssuers.Any(i => i.Replace("{tenantid}", tokenTenantId) == issuer))
                        return issuer;
                }
            }

            // Recreate the exception that is thrown by default
            // when issuer validation fails
            var validIssuer = parameters.ValidIssuer ?? "null";
            var validIssuers = parameters.ValidIssuers == null
                ? "null"
                : !parameters.ValidIssuers.Any()
                    ? "empty"
                    : string.Join(", ", parameters.ValidIssuers);
            string errorMessage = FormattableString.Invariant(
                $"IDX10205: Issuer validation failed. Issuer: '{issuer}'. Did not match: validationParameters.ValidIssuer: '{validIssuer}' or validationParameters.ValidIssuers: '{validIssuers}'.");

            throw new SecurityTokenInvalidIssuerException(errorMessage)
            {
                InvalidIssuer = issuer
            };
        }

        private bool validateEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
                return false;

            var atPos = email.LastIndexOf("@");
            if (atPos < 0)
                return false;

            email = email.ToLower();

            var validDomains = DEFAULT_VALID_DOMAINS;
            var validDomainsKeyVault = _configuration.GetSection("ValidDomains").Get<string>();

            if (!string.IsNullOrWhiteSpace(validDomainsKeyVault))
                validDomains = validDomainsKeyVault.Split(",", StringSplitOptions.RemoveEmptyEntries);

            var domain = email.Substring(atPos + 1);
            if (Array.IndexOf(validDomains, domain) >= 0)
                return true;

            return false;
        }
    }
}