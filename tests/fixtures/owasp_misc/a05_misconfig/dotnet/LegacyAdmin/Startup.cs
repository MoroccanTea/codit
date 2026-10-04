using System.IO;
using System.Xml;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Acme.LegacyAdmin
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // codit-expect: CWE-209 developer exception page enabled unconditionally (stack traces in production)
            app.UseDeveloperExceptionPage();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());
        }

        public static XmlDocument LoadFeed(Stream upload)
        {
            var doc = new XmlDocument();
            // codit-expect: CWE-611 XmlUrlResolver lets uploaded XML pull external entities
            doc.XmlResolver = new XmlUrlResolver();
            doc.Load(upload);
            return doc;
        }
    }
}
