using System.Security.Cryptography;
using CommonExtensions;
using CommonExtensions.Cryptography;
using Fedodo.BE.Auth.Models.DTO;
using Fedodo.NuGet.ActivityPub.Model.ActorTypes;
using Fedodo.NuGet.ActivityPub.Model.JsonConverters.Model;
using Fedodo.NuGet.Common.Constants;
using Fedodo.NuGet.Common.Interfaces;
using Fedodo.NuGet.Common.Models;
using Fedodo.NuGet.Common.Models.Webfinger;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;
using OpenIddict.Validation.AspNetCore;

namespace Fedodo.BE.Auth.Controllers;

[Route("User")]
[Produces("application/json")]
public class UserController : ControllerBase
{
    private readonly IAuthenticationHandler _authenticationHandler;
    private readonly IUserHandler _userHandler;
    private readonly ILogger<UserController> _logger;
    private readonly IMongoDbRepository _repository;

    public UserController(ILogger<UserController> logger, IMongoDbRepository repository,
        IAuthenticationHandler authenticationHandler, IUserHandler userHandler)
    {
        _logger = logger;
        _repository = repository;
        _authenticationHandler = authenticationHandler;
        _userHandler = userHandler;
    }

    [HttpPost]
    public async Task<ActionResult<Person>> CreateUserAsync(CreateUserDto userDto)
    {
        var rsa = RSA.Create();
        var actorId = Guid.NewGuid();

        var actor = await CreatePerson(userDto, rsa, actorId);

        if (actor.IsNull())
        {
            return BadRequest("Actor could not be created");
        }
        
        await CreateActorSecrets(rsa, actor);

        await CreateWebfinger(actor);

        // Create User
        User user = new();
        _authenticationHandler.CreatePasswordHash(userDto.Password, out var passwordHash, out var passwordSalt);
        user.Id = Guid.NewGuid();
        user.PasswordHash = passwordHash;
        user.PasswordSalt = passwordSalt;
        user.UserName = userDto.PreferredUsername;
        user.Role = "User";
        user.ActorIds = new[]
        {
            actorId.ToString()
        };

        await _repository.Create(user, DatabaseLocations.Users.Database, DatabaseLocations.Users.Collection);

        return Ok();
    }

    [HttpGet("Actors")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<ActionResult<IEnumerable<Uri>>> GetAllActors(Guid userId)
    {
        if (!_userHandler.VerifyUserId(userId, HttpContext)) return Forbid();

        var user = await _userHandler.GetUserByIdAsync(userId);
        
        return Ok(user.ActorIds);
    }    
    
    [HttpPost("Actors")]
    [Authorize(AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
    public async Task<ActionResult<IEnumerable<Uri>>> CreateActor(Guid userId, [FromBody]CreateActorDto actorDto)
    {
        if (!_userHandler.VerifyUserId(userId, HttpContext)) return Forbid();
        
        var rsa = RSA.Create();
        var actorId = Guid.NewGuid();
        
        var actor = await CreatePerson(actorDto, rsa, actorId);

        if (actor.IsNull())
        {
            return BadRequest("Actor could not be created");
        }
        
        await CreateActorSecrets(rsa, actor);

        await CreateWebfinger(actor);

        var user = await _userHandler.GetUserByIdAsync(userId);

        var temp = user.ActorIds!.ToList();
        temp.Add(actorId.ToString());
        user.ActorIds = temp;

        await _userHandler.UpdateUserAsync(user);

        return Ok();
    }
    
    private async Task<Person?> CreatePerson(CreateActorDto userDto, RSA rsa, Guid actorId)
    {
        var domainName = Environment.GetEnvironmentVariable("DOMAINNAME");

        var actor = new Person()
        {
            // Client generated
            Summary = userDto.Summary,
            PreferredUsername = userDto.PreferredUsername,
            Name = userDto.Name,

            // Server generated
            Id = new Uri($"https://{domainName}/actor/{actorId}"),
            Inbox = new Uri($"https://{domainName}/inbox/{actorId}"),
            Outbox = new Uri($"https://{domainName}/outbox/{actorId}"),
            Following = new Uri($"https://{domainName}/following/{actorId}"),
            Followers = new Uri($"https://{domainName}/followers/{actorId}"),
            Published = DateTime.Now,
            // Attachment = new TripleSet<Object>()
            // {
            //     Objects = new List<PropertyValue>()
            //     {
            //         
            //     }
            // },

            // Hardcoded
            Context = new TripleSet<Fedodo.NuGet.ActivityPub.Model.CoreTypes.Object>
            {
                StringLinks = new[]
                {
                    "https://www.w3.org/ns/activitystreams",
                    "https://w3id.org/security/v1"
                }
            }
        };
        
        actor.PublicKey = new Fedodo.NuGet.ActivityPub.Model.ActorTypes.SubTypes.PublicKey
        {
            Id = new Uri($"{actor.Id}#main-key"),
            Owner = actor.Id,
            PublicKeyPem = rsa.ExtractRsaPublicKeyPem()
        };

        // Add Actor if it is not exiting
        var filterDefinitionBuilder = Builders<Actor>.Filter;
        var filter = filterDefinitionBuilder.Where(i => i.PreferredUsername == actor.PreferredUsername);
        var exitingActor = await _repository.GetSpecificItem(filter, DatabaseLocations.Actors.Database,
            DatabaseLocations.Actors.Collection);
        if (exitingActor.IsNull())
        {
            await _repository.Create(actor, DatabaseLocations.Actors.Database, DatabaseLocations.Actors.Collection);
        }
        else
        {
            _logger.LogWarning("Wanted to create a User which already exists");

            return null;
        }

        return actor;
    }
    
    private async Task CreateWebfinger(Person actor)
    {
        var webfinger = new Webfinger
        {
            Subject = $"acct:{actor.PreferredUsername}@{Environment.GetEnvironmentVariable("DOMAINNAME")}",
            Links = new List<WebLink>
            {
                new()
                {
                    Rel = "self",
                    Href = actor.Id,
                    Type = "application/activity+json"
                }
            }
        };

        await _repository.Create(webfinger, DatabaseLocations.Webfinger.Database,
            DatabaseLocations.Webfinger.Collection);
    }

    private async Task CreateActorSecrets(RSA rsa, Person actor)
    {
        var actorSecrets = new ActorSecrets()
        {
            PrivateKeyActivityPub = rsa.ExtractRsaPrivateKeyPem(),
            ActorId = actor.Id!
        };

        await _repository.Create(actorSecrets, DatabaseLocations.ActorSecrets.Database,
            DatabaseLocations.ActorSecrets.Collection);
    }
}