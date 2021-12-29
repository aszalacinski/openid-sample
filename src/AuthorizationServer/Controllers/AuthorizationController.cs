
using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace AuthorizationServer.Controllers;

public class AuthorizationController : Controller
{
    [HttpPost("~/connect/token")]
    public IActionResult Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ?? throw new InvalidOperationException("The OpenId Connect request cannot be retrieved.");

        // this is NOT the same as the one used in the Account Login endpoint
        // THAT one is based on Cooke Authentication handler and is ONLY used within the context of the Auth server itself to
        // determin if the user has been authenticated or not.
        ClaimsPrincipal claimsPrincipal;

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
        else
        {
            throw new InvalidOperationException("The specified grant type is not supported.");
        }

        // returning a signinresult will ask openiddict to issue the appropriate access/identity tokens
        return SignIn(claimsPrincipal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
}