using Hotel.ATR.Portal.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Hotel.ATR.Portal.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IRepository _repo;

        private readonly IHttpContextAccessor _httpContext;
        private readonly IStringLocalizer<HomeController> _local;

        public HomeController(ILogger<HomeController> logger, IRepository repo, IHttpContextAccessor httpContext, IStringLocalizer<HomeController> local)
        {
            _logger = logger;
            _repo = repo;
            _httpContext = httpContext;
            _local = local;
        }


        public IActionResult AboutUs()
        {

           

            CookieOptions options = new CookieOptions();
            options.Expires = DateTime.Now.AddDays(1);
            
            string key = "IIN";
            string value = "021014550319";
            Response.Cookies.Append(key, value);
            Response.Cookies.Append("key_2", value);
            Response.Cookies.Append("key_3", value);



            return View();
        }
        [Authorize]
        public IActionResult Index(string culture, string cultureIU)
        {
            if (!string.IsNullOrEmpty(culture))
                {
                CultureInfo.CurrentCulture = new CultureInfo(culture);
                CultureInfo.CurrentUICulture = new CultureInfo(culture); 
            }
            ViewBag.AboutUs = _local["aboutus"];

            GetCulture(culture);


            HttpContext.Session.SetString("ATR.IIN", "021014550319");

            string value = HttpContext.Session.GetString("product");


            _logger.LogInformation("testInfo");
            _logger.LogError("testInfo");

            string email = "ok@ok.kz";
            _logger.LogWarning("testInfo: {email} - {logTime}",
                email, DateTime.Now);
            string key = "IIN";
            string value2= "021014550319";
            Response.Cookies.Append(key, value2);
            Response.Cookies.Append("key_2", value2);
            //var data1 = Request.Cookies["IIN"];
            //var data2 = _httpContext.HttpContext.Request.Cookies["IIN"];
            //Response.Cookies.Delete("IIN");
            //_httpContext.HttpContext.Response.Cookies.Delete("IIN");
            return View();
        }

        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult Login(string ReturnUrl)
        {
            ViewBag.ReturnUrl = ReturnUrl;

            return View();
        }

        [HttpPost]
        public IActionResult Login(string username, string password, string ReturnUrl)
        {

            if ((username == "admin") && (password == "admin"))
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username)
                };
                var claimsIdentity = new ClaimsIdentity(claims, "Login");

                HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

                return Redirect(ReturnUrl);
            }
            

            return View();
        }

        public IActionResult Logout()
        {
            HttpContext.SignOutAsync();
            return RedirectToAction("Index");
        }


        public string GetCulture(string code = "")
        {
            if (!string.IsNullOrWhiteSpace(code))
            {
                CultureInfo.CurrentCulture = new CultureInfo(code);
                CultureInfo.CurrentUICulture = new CultureInfo(code);

                ViewBag.Culture = string.Format("CurrentCulture: {0}, CurrentUICulture: {1}", CultureInfo.CurrentCulture,
                    CultureInfo.CurrentUICulture);
            }
            return "";
        }

    }
}
