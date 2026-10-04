using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace Acme.Sync.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/import")]
    public class ImportController : ControllerBase
    {
        [HttpPost("legacy-binary")]
        public IActionResult ImportBinary()
        {
#pragma warning disable SYSLIB0011
            // codit-expect: CWE-502 BinaryFormatter on the request body
            var state = new BinaryFormatter().Deserialize(Request.Body);
#pragma warning restore SYSLIB0011
            return Ok(state.GetType().Name);
        }



        [HttpPost("json")]
        public async Task<IActionResult> ImportJson()
        {
            // codit-safe: CWE-502 System.Text.Json into a fixed DTO type
            var state = await System.Text.Json.JsonSerializer.DeserializeAsync<SyncState>(Request.Body);
            return Ok(state?.Id);
        }



        [HttpPost("legacy-typed")]
        public async Task<IActionResult> ImportTyped()
        {
            using var reader = new StreamReader(Request.Body);
            var body = await reader.ReadToEndAsync();
            // codit-expect: CWE-502 TypeNameHandling.All lets the payload choose the CLR type ($type gadget)
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
            var state = JsonConvert.DeserializeObject(body, settings);
            return Ok(state?.GetType().Name);
        }



        [HttpPost("typed")]
        public async Task<IActionResult> ImportTypedSafe()
        {
            using var reader = new StreamReader(Request.Body);
            var body = await reader.ReadToEndAsync();
            // codit-safe: CWE-502 TypeNameHandling.None, concrete target type
            var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
            var state = JsonConvert.DeserializeObject<SyncState>(body, settings);
            return Ok(state?.Id);
        }
    }

    public class SyncState
    {
        public string Id { get; set; }
    }
}
