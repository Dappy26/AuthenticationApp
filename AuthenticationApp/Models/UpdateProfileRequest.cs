using System.ComponentModel.DataAnnotations;
namespace AuthenticationApp.Models;

public class UpdateProfileRequest
{
    [Required(ErrorMessage = "Full name is required.")]
    [MaxLength(100, ErrorMessage = "Full name cannot exceed 100 characters.")]
    public string FullName { get; set; } = string.Empty;
}
