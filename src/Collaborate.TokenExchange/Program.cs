using Collaborate.TokenExchange;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCollaborateTokenExchange(builder.Configuration);
builder.Services.AddControllers();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

public partial class Program;
