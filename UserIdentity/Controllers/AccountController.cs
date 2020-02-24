using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using UserIdentity.Identity;
using UserIdentity.Models;

namespace UserIdentity.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {

        private UserManager<ApplicationUser> _userManager;

        public AccountController()
        {
            _userManager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new IdentityDataContext()));

            _userManager.PasswordValidator = new CustomerPasswordValidator()
            {
                RequireDigit = true,
                RequiredLength = 7,
                RequireUppercase = true,
                RequireLowercase = true,
                RequireNonLetterOrDigit = true
            };

            _userManager.UserValidator = new UserValidator<ApplicationUser>(_userManager)
            {
                RequireUniqueEmail = true,
                AllowOnlyAlphanumericUserNames = false
            };

        }

        // GET: Account
        public ActionResult Index()
        {
            return View();
        }


        [HttpGet]
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                return View("Error", new string[] {"Erişim Hakkınız Yok"});
            }

            ViewBag.returnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public ActionResult Login(LoginModel model,string returnUrl)
        {
            if (ModelState.IsValid)
            {


                var user = _userManager.Find(model.Name, model.Password);
                if (user == null)
                {
                    ModelState.AddModelError("", "Yanlis Sifre yada kullanici adi");
                }
                else
                {
                    var authManager = HttpContext.GetOwinContext().Authentication;
                    var identity = _userManager.CreateIdentity(user, "ApplicationCokie");
                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = true
                    };

                    authManager.SignOut();
                    authManager.SignIn(authProperties, identity);

                    TempData["user"] = user;

                    return Redirect(string.IsNullOrEmpty(returnUrl) ? "/" : returnUrl);
                }
            }

            

            ViewBag.returnUrl = returnUrl;
            return View(model);
        }


        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }



        [HttpPost]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public ActionResult Register(Register model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser();
                user.UserName = model.Name;
                user.Email = model.Email;

                var result = _userManager.Create(user, model.Password);

                if (result.Succeeded)
                {
                    _userManager.AddToRole(user.Id, "User");
                    return RedirectToAction("Login");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError("",error);
                    }
                }
            }
            
            return View(model);
        }


        public ActionResult Logout()
        {
            var authManager = HttpContext.GetOwinContext().Authentication;
            authManager.SignOut();

            return RedirectToAction("Login");
        }
    }
}