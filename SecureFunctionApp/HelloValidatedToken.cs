using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using SecureFunctionApp.Services;
using System.Diagnostics;

namespace SecureFunctionApp
{
    public class HelloValidatedToken
    {
        private readonly SecurityService _securityService;

        public HelloValidatedToken(SecurityService securityService)
        {
            _securityService = securityService;
        }

        [FunctionName("HelloValidatedToken")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            var validatedToken = await _securityService.GetValidatedToken(req, log);

            if (validatedToken == null)
            {
                return new UnauthorizedResult();
            }

            foreach (var item in validatedToken.Claims)
            {
                Debug.WriteLine($"{item.Type}: {item.Value}");
            }

            Debug.WriteLine($"Token subject: {validatedToken.Subject}");

            Debug.WriteLine($"Valid from: {validatedToken.ValidFrom}");

            Debug.WriteLine($"Valid to: {validatedToken.ValidTo}");

            var name = validatedToken.Subject;

            return name != null
                ? (ActionResult)new OkObjectResult($"Hello, {name}")
                : new BadRequestObjectResult("Unable to determine user identity.");
        }
    }
}
