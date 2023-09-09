using Microsoft.AspNetCore.Mvc;
using MyWebApplication.Models.EntityManager;
using MyWebApplication.Models.ViewModel;

namespace MyWebApplication.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult SignUp()
        {
            return View();
        }

        [HttpPost]
        public ActionResult SignUp(UserModel user)
        {
            if (ModelState.IsValid)
            {
                UserManager um = new UserManager();
                if (!um.IsLoginNameExist(user.LoginName))
                {
                    um.AddUserAccount(user);
                    // FormsAuthentication.SetAuthCookie(user.FirstName, false);
                    return RedirectToAction("","Home");
                }
                else
                    ModelState.AddModelError("", "Login Name already taken.");
            }
            return View();
        }

        [HttpGet]
        public ActionResult GetUsers()
        {
            var users = new UserManager().GetAllUsers();

            return View();
        }
    }
}