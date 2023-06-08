using System.ComponentModel.DataAnnotations;

namespace Fedodo.BE.Auth.Models.DTO;

public class CreateUserDto : CreateActorDto
{
    [Required] public string? Password { get; set; }
}