var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseSwagger(c => c.RouteTemplate = "auth/swagger/{documentname}/swagger.json");
app.UseSwaggerUI(c => c.RoutePrefix = "auth/swagger");

app.UseAuthorization();

app.MapControllers();

app.Run();