using System.Xml;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddProblemDetails();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    // codit-safe: CWE-209 developer exception page only in the Development environment
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler();
    app.UseHsts();
}



app.MapPost("/import", (HttpRequest request) =>
{
    // codit-safe: CWE-611 DTDs prohibited and no resolver
    var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
    using var reader = XmlReader.Create(request.Body, settings);
    var doc = new XmlDocument { XmlResolver = null };
    doc.Load(reader);
    return doc.DocumentElement?.ChildNodes.Count ?? 0;
});

app.MapControllers();
app.Run();
