using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MyWebApplication.Models.EntityManager;
using MyWebApplication.Models.ViewModel;
using MyWebApplication.Security;
using System.Security.Claims;

namespace MyWebApplication.Controllers
{

    public class AccountController : Controller
    {
        public ActionResult SignUp()
        {
            return View();
        }
        //public SignInManager<string> _signInManager;
        public ActionResult Login()
        {
            return View();
        }
        
        public ActionResult MyProfile()
        {
            UserManager um = new UserManager();
            string currentLoginName = User.Identity.Name; // Get the username of the logged-in user

            UsersModel user = um.GetUserByUserName(currentLoginName); // Replace with your service method

            if (user == null)
            {
                return NotFound(); // Handle the case when the user is not found
            }

            return View(user);
        }
        [AuthorizeRoles("Admin")]
        public ActionResult Users()
        {
            UserManager um = new UserManager();
            UsersModel user = um.GetAllUsers();

            return View(user);
        }

        [HttpPost]
        public ActionResult SignUp(UserModel user)
        {
            ModelState.Remove("AccountImage");
            ModelState.Remove("RoleName");

            if (ModelState.IsValid)
            {
                UserManager um = new UserManager();
                if (!um.IsLoginNameExist(user.LoginName))
                {
                    um.AddUserAccount(user);
                    // FormsAuthentication.SetAuthCookie(user.FirstName, false);
                    return RedirectToAction("", "Home");
                }
                else
                    ModelState.AddModelError("", "Login Name already taken.");
            }
            return View();
        }

        [HttpPut]
        public async Task<ActionResult> Update([FromBody] UserModel userData)
        {
            ModelState.Remove("Password");

            UserManager um = new UserManager();
            if (um.IsLoginNameExist(userData.LoginName))
            {
                um.UpdateUserAccount(userData);
                // Added a return Ok() statement to indicate success
                return Ok();
            }
            // Handle the case when the login name doesn't exist, e.g., return a relevant error response
            return NotFound();
        }

        [HttpPost]
        public ActionResult LogIn(UserLoginModel ulm)
        {
            if (ModelState.IsValid)
            {
                UserManager um = new UserManager();

                if (um.IsLoginNameExist(ulm.LoginName)) // Check if the email exists in the database
                {
                    var storedPassword = um.GetUserPassword(ulm.LoginName); // Retrieve the stored password from the database

                    if (string.IsNullOrEmpty(ulm.Password))
                    {
                        ModelState.AddModelError("", "Please enter your password.");
                    }
                    else if (ulm.Password == storedPassword) // Compare the provided password with the stored password
                    {
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, ulm.LoginName)
                        };

                        var userIdentity = new ClaimsIdentity(claims, "login");

                        ClaimsPrincipal principal = new ClaimsPrincipal(userIdentity);

                        // Sign in the user using Cookie Authentication
                        HttpContext.SignInAsync(principal);

                        // Redirect to the desired action (e.g., "Users")
                        return RedirectToAction("Index", "Home");
                    }
                    else
                    {
                        ModelState.AddModelError("", "The password provided is incorrect.");
                    }
                }
                else
                {
                    ModelState.AddModelError("", "The provided email address does not exist.");
                }
            }

            // If authentication fails or ModelState is invalid, redisplay the login form
            return View();
        }

        [HttpPost]
        public ActionResult LogOut()
        {
            HttpContext.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
