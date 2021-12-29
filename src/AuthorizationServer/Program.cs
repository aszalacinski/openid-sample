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
        // machine to machine communication
        // looking for a client_id and a client_secret
        options.AllowClientCredentialsFlow();

        options.SetTokenEndpointUris("/connect/token");

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
            .EnableTokenEndpointPassthrough();
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

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.Run();
