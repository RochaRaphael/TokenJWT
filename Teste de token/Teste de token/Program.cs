

using Konscious.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.Intrinsics.X86;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;


Console.WriteLine("Digite o cpf");
string doc = Console.ReadLine();

JWTAndHash jwt = GerarJWT(doc);
Console.WriteLine("Resultado do JWT: " + jwt.Token);

Console.WriteLine("Descriptografando JWT...");
var resultado = ExtrairDocJWT(jwt.Token); 

Console.WriteLine("Doc extraido do JWT: " +  resultado);


static JWTAndHash GerarJWT(string doc)
{
    string chaveSecreta = "8fGYW4Hqfu7SpEsH!?JR";

    int randomNumber = GerarNumeroAleatorio();
    //Gerando hash com argon2 + salt
    var hash = GenerateHash(randomNumber.ToString());

    // Ajusta a chave para garantir que tenha pelo menos 256 bits (32 bytes)
    byte[] chaveBytes = Encoding.UTF8.GetBytes(chaveSecreta);
    Array.Resize(ref chaveBytes, 32); // Ajusta o tamanho para 32 bytes, preenchendo com zeros se necessário

    // Cria as credenciais usando a chave de segurança e o algoritmo de assinatura
    var credenciais = new SigningCredentials(
        new SymmetricSecurityKey(chaveBytes),
        SecurityAlgorithms.HmacSha256);

    // Adiciona as reivindicações ao token
    var claims = new List<Claim>
            {
                new Claim("cpf", doc),
                new Claim("hash", hash)
            };

    // Cria o token
    var token = new JwtSecurityToken(
        issuer: "auth-api",
        audience: "api-client",
        claims: claims,
        expires: DateTime.UtcNow.AddDays(30),
        signingCredentials: credenciais
    );

    // Converte o token em uma string JWT
    var tokenHandler = new JwtSecurityTokenHandler();
    string jwtToken = tokenHandler.WriteToken(token);

    return new JWTAndHash { Token = jwtToken, Hash = hash };
}


static string ExtrairDocJWT(string jwt)
{
    if (!VerificarToken(jwt)) throw new Exception("Erro.");

    // Decodifica o JWT
    var handler = new JwtSecurityTokenHandler();
    var jsonToken = handler.ReadToken(jwt) as JwtSecurityToken;

    // Obtém a reivindicação "cpf" do payload
    string cpf = jsonToken?.Payload["cpf"]?.ToString();
    string random = jsonToken?.Payload["hash"]?.ToString();

    return "CPF: " + cpf + " CHAVE RANDOM: " + random;
}

static bool VerificarToken(string jwtToken)
{
    string chaveSecreta = "8fGYW4Hqfu7SpEsH!?JR";
    // Converte a chave secreta para bytes
    byte[] chaveBytes = Encoding.UTF8.GetBytes(chaveSecreta);
    Array.Resize(ref chaveBytes, 32); // Ajusta o tamanho para 32 bytes, preenchendo com zeros se necessário

    // Configura a chave de segurança com a chave secreta
    var chaveSeguranca = new SymmetricSecurityKey(chaveBytes);

    // Configura os parâmetros de validação do token
    var parametrosValidacao = new TokenValidationParameters
    {
        ValidateIssuer = true, // Valida o emissor (iss)
        ValidIssuer = "auth-api", // Define o emissor válido
        ValidateAudience = true, // Valida a audiência (aud)
        ValidAudience = "api-client", // Define a audiência válida
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = chaveSeguranca
    };

    try
    {
        // Valida o token
        var tokenHandler = new JwtSecurityTokenHandler();
        SecurityToken securityToken;
        var principal = tokenHandler.ValidateToken(jwtToken, parametrosValidacao, out securityToken);
        return true; // Se a validação for bem-sucedida, o token é válido
    }
    catch (SecurityTokenException)
    {
        return false; // Se ocorrer uma exceção de segurança, o token é inválido
    }
}

static int GerarNumeroAleatorio()
{
    using (var rng = new RNGCryptoServiceProvider())
    {
        byte[] randomNumberBytes = new byte[4];
        rng.GetBytes(randomNumberBytes);
        return BitConverter.ToInt32(randomNumberBytes, 0);
    }
}



static string GenerateHash(string password)
{
    int saltSize = 16; // Define o tamanho do salt em bytes
    int hashSize = 32; // Define o tamanho do hash em bytes

    var salt = new byte[saltSize]; // Cria um array de bytes para o salt
    var rng = new RNGCryptoServiceProvider(); // Cria um gerador de números aleatórios criptográficos
    rng.GetBytes(salt); // Gera um salt aleatório usando o RNG criptográfico

    var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password)); // Cria um objeto Argon2id usando a senha como entrada

    argon2.Salt = salt; // Define o salt para o objeto Argon2id
    argon2.DegreeOfParallelism = 8; // Define o grau de paralelismo para 8
    argon2.Iterations = 4; // Define o número de iterações para 4
    argon2.MemorySize = 1024 * 1024; // Define o tamanho da memória em bytes para 1 GB

    byte[] hash = argon2.GetBytes(hashSize); // Gera o hash da senha usando o objeto Argon2id

    byte[] hashBytes = new byte[saltSize + hashSize]; // Cria um array de bytes para armazenar o salt e o hash
    Array.Copy(salt, 0, hashBytes, 0, saltSize); // Copia o salt para o início do array de bytes
    Array.Copy(hash, 0, hashBytes, saltSize, hashSize); // Copia o hash para o final do array de bytes

    return Convert.ToBase64String(hashBytes);

}

public class Password
{
    public string Hash { get; set; }
    public string Salt { get; set; }
}
class JWTAndHash
{
    public string Token { get; set; }
    public string Hash { get; set; }
}