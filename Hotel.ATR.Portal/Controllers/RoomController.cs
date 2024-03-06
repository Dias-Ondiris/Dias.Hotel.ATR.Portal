using Hotel.ATR.Portal.Models;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Hotel.ATR.Portal.Controllers
{
    public class RoomController : Controller
    {
        private IWebHostEnvironment hostEnv;
        public RoomController(IWebHostEnvironment hostEnv)
        {
            this.hostEnv = hostEnv;
        }

        public IActionResult Index(string email)
        {
            ViewBag.CurrentTime = DateTime.Now.ToString();
            TempData["CurrentTimeTD"] = DateTime.Now.ToString();
            return View((object)email);
        }

        public ContentResult IndexText()
        {
            string message = "some text";
            return Content(message, "text/plain", Encoding.Default);
        }
         
        //public JsonResult IndexBeep()
        //{
        //    string message = "some text";
        //    return Json(message, JsonRequestBehavior.AllowGet);
        //}

        public FileResult GetFile()
        {
            string path = Path.Combine(hostEnv.WebRootPath, "style.css");

            return File(path, "text/plain", "FileName.css");
        }
        public IActionResult RoomList()
        {
            return View();
        }

        public IActionResult RoomDetails()
        {
            return View();
            //return View("Index");
            //return RedirectToAction("RoomList");
        }

        [HttpPost]
        public async Task< IActionResult> CreateSubscribe(IFormFile photo, User  user)//string email
        {
            string path = Path.Combine(hostEnv.WebRootPath, photo.FileName);
            using (var stream = new FileStream(path, FileMode.Create))
            {
               await photo.CopyToAsync(stream);
            }

            //return View("~/Views/Home/Privacy.cshtml");
            ///TODO
            return View("Index", new { email= user.email } );

        }
    }
}
