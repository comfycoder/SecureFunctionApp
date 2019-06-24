using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecureFunctionApp.Services;
using System.IO;

[assembly: FunctionsStartup(typeof(SecureFunctionApp.Startup))]
namespace SecureFunctionApp
{
    // Use dependency injection in .NET Azure Functions
    // https://docs.microsoft.com/en-us/azure/azure-functions/functions-dotnet-dependency-injection
    // View or download a sample of different service lifetimes on GitHub.
    // https://github.com/Azure/azure-functions-dotnet-extensions/tree/master/src/samples/DependencyInjection/Scopes
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            // https://blog.jongallant.com/2018/01/azure-function-config/

            var basePath = Directory.GetCurrentDirectory();

            var config = new ConfigurationBuilder()
                .SetBasePath(basePath)
                .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();

            builder.Services.AddSingleton<SecurityService>();
        }
    }
}
