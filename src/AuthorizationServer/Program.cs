using AuthorizationServer.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/account/login";
    });

builder.Services.AddDbContext<DbContext>(options =>
{

    // configure the context to use an in-memory store
    options.UseInMemoryDatabase(nameof(DbContext));

    // register the entity sets needed by OpenIddict
    options.UseOpenIddict();
});

builder.Services.AddOpenIddict()

    // Register the OpenIddict core components
    .AddCore(options =>
    {
        // Configure OpenIddict to use the EF Core stores/models.
        options.UseEntityFrameworkCore()
            .UseDbContext<DbContext>();
    })

    // Register the OpenIddict server components
    .AddServer(options =>
    {
        // authorization code flow with PKCE extension
        // client apps that need a user to login to use them, i.e. SPA or mobile apps
        options
            .AllowAuthorizationCodeFlow()
                // require PKCE
                .RequireProofKeyForCodeExchange()
            // machine to machine communication
            // looking for a client_id and a client_secret
            .AllowClientCredentialsFlow()
            // allow refresh tokens
            // request needs to ask for the 'offline_access' scope to include a refresh token
            // subsequent calls by the client to the token endpoint can use the refresh token instead of the access token
            .AllowRefreshTokenFlow();

        options
            .SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token")
            .SetUserinfoEndpointUris("/connect/userinfo");

        // Encryption and signing of tokens
        // this is development configuration
        // for production, need to use .AddEncryptionKey(key) and .AddSigningKey(key)
        // and remove the DiableAccessTokenEncryption()
        options
            .AddEphemeralEncryptionKey()
            .AddEphemeralSigningKey()
            .DisableAccessTokenEncryption();

        // Register scopes
        // can register multple via ['scope1', 'scope2', 'etc']
        options.RegisterScopes("api");

        // Register the ASP.NET Core host and configure the ASP.NET Core specific options.
        options
            .UseAspNetCore()
            .EnableTokenEndpointPassthrough()
            .EnableAuthorizationEndpointPassthrough()
            .EnableUserinfoEndpointPassthrough();
    });

builder.Services.AddHostedService<TestData>();

builder.Services.AddControllersWithViews();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.Run();
