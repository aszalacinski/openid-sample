
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace AuthorizationServer.Controllers;

public class AuthorizationController : Controller
{
    // token endpoint
    [HttpPost("~/connect/token"), Produces("application/json")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenId Connect request cannot be retrieved.");

        // this is NOT the same as the one used in the Account Login endpoint
        // THAT one is based on Cooke Authentication handler and is ONLY used within the context of the Auth server itself to
        // determin if the user has been authenticated or not.
        ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal();

        if (request.IsClientCredentialsGrantType())
        {
            // NOTE: the client credentials are automatically validated by OpenIddict:
            // if client_id or client_secret are invalid, this action won't be invoked

            var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

            // Subject (sub) is a required field, we use the client id as the subject identifier here.
            identity.AddClaim(OpenIddictConstants.Claims.Subject, request.ClientId ?? throw new InvalidOperationException());

            // access user application profile details here via a service call to set claims specific to the application

            // add some claim, don't forget to add destination otherwise it won't be added to the access token.
            identity.AddClaim("some-claim", "some-value", OpenIddictConstants.Destinations.AccessToken);

            claimsPrincipal = new ClaimsPrincipal(identity);

            // grant all requested scopes here
            // OpenIddict has already checked if the requested scopes are allowed (as a whole and for the current client)
            // the reason we add the scopes manually here is that we are able to filter the scopes granted here if we want to
            claimsPrincipal.SetScopes(request.GetScopes());
        }
        else if (request.IsAuthorizationCodeGrantType())
        {
            // retrieve the claims principal stored in the authorization code

            var retrievedPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

            if (retrievedPrincipal is not null)
            {
                claimsPrincipal = retrievedPrincipal;
            }
        }
        else if (request.IsRefreshTokenGrantType())
        {
            // Retrieve the claims principal stored in the refresh token.
            var retrievedPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

            if (retrievedPrincipal is not null)
            {
                claimsPrincipal = retrievedPrincipal;
            }
        }
        else
        {
            throw new InvalidOperationException("The specified grant type is not supported.");
        }

        // returning a signinresult will ask openiddict to issue the appropriate access/identity tokens
        return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // auth endpoint
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenId connect request cannot be retrieved");

        // retrieve the user principal stored in the authentication cookie.
        var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // if the user principal can't be extracted, redirect the user to the login page
        // cookie wasn't there or is stale
        // redirect user back to login and note that it will redirect to authorize on successful login
        if (!result.Succeeded)
        {
            return Challenge(
                authenticationSchemes: CookieAuthenticationDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                        Request.HasFormContentType ? Request.Form.ToList() : Request.Query.ToList()
                    )
                }
            );
        }

        string subject = string.Empty;

        if (result.Principal is not null && result.Principal.Identity is not null)
        {
            subject = result.Principal.Identity.Name ?? string.Empty;
        }

        // create a new claims principal
        var claims = new List<Claim> {
            // 'subject' claim which is required
            new Claim(OpenIddictConstants.Claims.Subject, subject),

            
            // add some claim, don't forget to add destination as 'access_token' otherwise it won't be added to the access token.
            // subject above is required and is always added to access token
            new Claim("some claim", "some value").SetDestinations(OpenIddictConstants.Destinations.AccessToken ),

            // access user application profile details here via a service call to set user info claims specific to the application
            // set the email claim for the user_info endpoint... wont' appear in the access token
            new Claim(OpenIddictConstants.Claims.Email, "some.email@mailinator.com").SetDestinations(new List<string>{OpenIddictConstants.Destinations.AccessToken,OpenIddictConstants.Destinations.IdentityToken}),
            // set the following token for user info endpoint only
            new Claim(OpenIddictConstants.Claims.PhoneNumber, "111-111-1111").SetDestinations(OpenIddictConstants.Destinations.IdentityToken)
        };

        var claimsIdentity = new ClaimsIdentity(claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // this is NOT the same as the one used in the Account Login endpoint
        // THAT one is based on Cooke Authentication handler and is ONLY used within the context of the Auth server itself to
        // determin if the user has been authenticated or not.
        var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

        // set the requested scopes (this is not done automatically)
        // grant all requested scopes here
        // OpenIddict has already checked if the requested scopes are allowed (as a whole and for the current client)
        // the reason we add the scopes manually here is that we are able to filter the scopes granted here if we want to
        // note... a consent screen selected options would be where we would filter out scopes
        claimsPrincipal.SetScopes(request.GetScopes());

        // signing in with the openiddict authentication scheme trigger OpenIddict to issue a code (which can be exchanged for an access token)
        return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        var claimsPrincipal = (await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

        if (claimsPrincipal is not null)
        {
            // get claims from claims principal OR
            // access user application profile details here via a service call to set user info claims specific to the application

            return Ok(new
            {
                Name = claimsPrincipal.GetClaim(OpenIddictConstants.Claims.Subject),
                Email = claimsPrincipal.GetClaim(OpenIddictConstants.Claims.Email),
                Company = "Happy App Software",
                Occupation = "Developer",
            });
        }
        else
        {
            return new EmptyResult();
        }
    }
}