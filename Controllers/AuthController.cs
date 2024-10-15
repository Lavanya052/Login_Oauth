using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Login_Oauth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpGet("signin-google")]
        public IActionResult SignInWithGoogle()
        {
            var redirectUrl = Url.Action("GoogleResponse", "Auth", null, Request.Scheme);
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(GoogleDefaults.AuthenticationScheme);

            if (!authenticateResult.Succeeded)
            {
                // Optionally, redirect to an error page or return a response
                return Redirect("https://localhost:4200/login?error=GoogleAuthenticationFailed");
            }

            var claims = authenticateResult.Principal.Claims.ToList();
            var jwtToken = GenerateJwtToken(claims);

            var response = new
            {
                token = jwtToken,
                user = new
                {
                    name = authenticateResult.Principal.Identity?.Name,
                    email = authenticateResult.Principal.FindFirst(ClaimTypes.Email)?.Value
                }
            };

            // Optionally, redirect to a frontend URL with the token as a query parameter
            var frontendRedirectUrl = $"https://localhost:4200/callback?token={jwtToken}";
            return Redirect(frontendRedirectUrl);

            // Alternatively, return the response as JSON
            // return Ok(response);
        }

        private string GenerateJwtToken(IEnumerable<Claim> claims)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");

            var secret = jwtSettings["Secret"] ?? throw new InvalidOperationException("JWT Secret is not configured.");
            var issuer = jwtSettings["Issuer"] ?? "defaultIssuer";
            var audience = jwtSettings["Audience"] ?? "defaultAudience";
            var expirationInMinutes = double.TryParse(jwtSettings["ExpirationInMinutes"], out var result) ? result : 60;

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.Now.AddMinutes(expirationInMinutes),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
