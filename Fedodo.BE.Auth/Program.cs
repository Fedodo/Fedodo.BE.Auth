// https://dev.to/robinvanderknaap/setting-up-an-authorization-server-with-openiddict-part-i-introduction-4jid

using Fedodo.BE.Auth;
using Microsoft.AspNetCore.Authentication.Cookies;
using MongoDB.Driver;

var startup = new Startup();
var connectionString =
    $"mongodb+srv://{Environment.GetEnvironmentVariable("MONGO_USERNAME")}:{Environment.GetEnvironmentVariable("MONGO_PASSWORD")}@{Environment.GetEnvironmentVariable("MONGO_HOSTNAME")}/?retryWrites=true&w=majority";
var mongoClient = new MongoClient(connectionString);

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => { options.LoginPath = "/account/login"; });

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

startup.AddOpenIdDict(builder, mongoClient);

await startup.CreateMongoDbIndexes(builder);

startup.SetupMongoDb();

startup.AddCustomServices(builder, mongoClient);

builder.WebHost.UseUrls("http://*:");

var app = builder.Build();

app.Use((context, next) =>
{
    context.Request.Scheme = "https";

    return next();
});

app.UseSwagger();
app.UseSwaggerUI();

app.UseCors(x => x.AllowAnyHeader()
    .AllowAnyMethod()
    .WithOrigins("*"));

app.UseStaticFiles();

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseEndpoints(options =>
{
    options.MapRazorPages();
    options.MapControllers();
    options.MapFallbackToFile("index.html");
});

app.Run();