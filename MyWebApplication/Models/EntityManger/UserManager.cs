using System;
using System.Linq;
using MyWebApplication.Models.DB;
using MyWebApplication.Models.ViewModel;

namespace MyWebApplication.Models.EntityManager
{
    public class UserManager
    {
        public void AddUserAccount(UserModel user)
        {
            using (MyDBContext db = new MyDBContext())
            {
                //Add checking here if login exists

                SystemUsers newSysUser = new SystemUsers
                {
                    LoginName = user.LoginName,
                    CreatedBy = 1,
                    PasswordEncryptedText = user.Password, //this has to be encrypted
                    CreatedDateTime = DateTime.Now,
                    ModifiedBy = 1,
                    ModifiedDateTime = DateTime.Now
                };

                db.SystemUsers.Add(newSysUser);
                db.SaveChanges();

                int newUserId = db.SystemUsers.First(u => u.LoginName == newSysUser.LoginName).UserID;

                Users newUser = new Users
                {
                    UserID = newUserId,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Gender = "1",
                    CreatedBy = 1,
                    CreatedDateTime = DateTime.Now,
                    ModifiedBy = 1,
                    ModifiedDateTime = DateTime.Now
                };

                db.Users.Add(newUser);
                db.SaveChanges();
            }
        }
        public List<Users> GetAllUsers()
        {
            List<Users> users = new List<Users>();

            using (MyDBContext db = new MyDBContext())
            {
                users = db.Users.ToList();
            }

            return users;
        }
         public bool IsLoginNameExist(string loginName)
        {
            using (MyDBContext db = new MyDBContext())
            {
                return db.SystemUsers.Where(u =>u.LoginName.Equals(loginName)).Any();
            }
        }
    }
}
