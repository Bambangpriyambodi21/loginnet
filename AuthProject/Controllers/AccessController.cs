using Microsoft.AspNetCore.Mvc;

using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using AuthProject.Models;
using System.Data.SqlClient;

namespace AuthProject.Controllers
{
    public class AccessController : Controller
    {
        public IActionResult Login()
        {
            ClaimsPrincipal claimsUser = HttpContext.User;
            if (claimsUser.Identity.IsAuthenticated)
                return RedirectToAction("Index", "Home");

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(VMLogin modelLogin)
        {
            string connectionString = @"Data Source = (localdb)\MSSQLLocalDB; Initial Catalog = MVCCRUD; Integrated Security = True";
            string query = "SELECT COUNT(1) FROM mahasiswa where Nama_Mhs=@Nama_Mhs and Nim=@Nim";
            bool dataExists = false;

            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Nama_Mhs", modelLogin.Email);
                    command.Parameters.AddWithValue("@Nim", modelLogin.PassWord);

                    connection.Open();
                    int count = (int)command.ExecuteScalar();
                    dataExists = (count > 0);
                    connection.Close();
                }
            }

            if (dataExists == true)
            {
                List<Claim> claims = new List<Claim>()
                {
                    new Claim(ClaimTypes.NameIdentifier, modelLogin.Email),
                    new Claim("OtherProperties","Example Role")
                };

                ClaimsIdentity identity = new ClaimsIdentity(claims,
                    CookieAuthenticationDefaults.AuthenticationScheme);

                AuthenticationProperties properties = new AuthenticationProperties()
                {
                    AllowRefresh = true,
                    IsPersistent = modelLogin.KeepLoggedIn
                };

                await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(identity), properties);

                return RedirectToAction("index", "home");
            }

            ViewData["ValidateMessage"] = "user not found";
            return View();
        }
    }
}
