# Adding Encryption to ASP.NET Core Identity and Entity Framework

Firstly let us be clear - this is a sample project meant to demonstrate 
the capability for developer based encryption in ASP.NET Core Identity 
2.1. It is not meant to demonstrate best practice, as it is likely that your 
business has unique requirements, be they regulatory (HIPAA, GDPR, PCI etc.)
or culture driven and no sample can take that into account. You should work
with your privacy champions or consultants to work out what is right for 
your circumstances. 

This sample is not supported by Microsoft. If you roll your own encryption 
you risk losing data if you do it wrong. Basically **don't do this** if you
can at all help it.

## Use your database or operating system capabilities first

Some databases or storage mechanisms allow for encryption at rest, 
encrypting your stored data with no work needed for any software that 
accesses the data. This is, by far, the easiest and safest option; let
the database manage keys and encryption for you. Using the manual encryption
providers should be viewed as a **last resort**.

For example, Microsoft SQL and Azure SQL provide 
[Transparent Data Encryption](https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption?view=sql-server-2017) (TDE), 
and Azure has encrypted SQL database by default since [May 2017](https://azure.microsoft.com/en-us/updates/newly-created-azure-sql-databases-encrypted-by-default/), as well as
encrypting blobs, files, tables and queue storage since [August 2017](https://azure.microsoft.com/en-us/updates/newly-created-azure-sql-databases-encrypted-by-default/).

For databases that don't provide built-in encryption at rest, 
you may be able to use disk encryption, such as [Bitlocker](https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-how-to-deploy-on-windows-server) 
to provide the same protections. Linux has encrypted file systems so as [eCryptfs](https://launchpad.net/ecryptfs) and [EncFS](https://github.com/vgough/encfs). 

## But my server admins won't encrypt ...

Your risk assessment, or your server administrators, 
may have decided that full disk encryption is not suitable
for your needs, and you must encrypt personal data "manually". 
ASP.NET Core Identity 2.1 has the facility for you to add encryption and
decryption that runs within the application before the data is written to the database.

This approach requires that you understand the fundamentals of encryption. 
It is also worth noting that encrypted data is going to take up more space than unencrypted data.
For example, encrypting "bob@contoso.com" changes the 15 characters normally taken to 194 characters, 
because we can't change the underlying schema to be binary and not strings. 
You will be responsible for safely storing your keys and ensuring they are
not lost. You may end up with truncated data. 

To repeat, this approach is a **last resort**.

## Implementing ASP.NET Identity manual encryption

Identity provides two interfaces to protect your data: 
`ILookupProtector` used by the User manager, and 
`IPersonalDataProtector` which is used by Entity Framework.
At a minimum you must implement an instance of `ILookupProtector`.
The default implementation of `IPersonalDataProtector` uses `ILookupProtector`.

### <a name="cryptoAgility"></a> Crypto Agility

Before you get started down this (again, **last resort**) path you need to think about crypto agility. The last
few years have seen various cryptographic algorithms fall by the wayside. At some point, no matter
what you pick, you're going to have to switch your algorithms to a new one. This sample embeds an algorithm
identifier in the cipher text which will allow for the implementation of new algorithm choices.

In order to address this in the sample I use [ProtectorAlgorithmHelper](AspNetCoreIdentityEncryption\ProtectorAlgorithmHelper.cs).
This contains an `enum` which is used to identify the algorithms used, and a corresponding class which returns the current 
algorithm identifier, and also creates the algorithms for an identifier.

### Managing keys

ASP.NET Core Identity protection provides a basic interface to allow you to manage
and rotate keys: `ILookupProtectorKeyRing`. When data is protected the
your protected should ask the key ring for the corresponding key for the 
`keyId` it's passed. You then use that to protect the data, or if you
want to be more secure, use the key provided as a master key, with 
key derivation used to produce keys for encryption and decryption, and
for authenticated signatures. When unprotecting the data, get the key for the 
specified `keyId`, retrieve that key from the key ring, and go through the process in reverse.
ASP.NET Core Identity will prepend your data with the key identifier used to encrypt the plain text.

The key ring also has a property: `CurrentKeyId`. This is the identifier 
for what key will be used to protect new data. This property can be used 
to provide key rotation, with a new id being returned when keys rotate according 
to your requirements.

Thus before we can protect and unprotect we need to implement a keyring.
To provide a simple example we're going to generate and persist a symmetric
key based on the default algorithm from the [algorithm helper](#cryptoAgility). 

Key storage is out of scope for the framework as it is dependent on your requirements 
(again driven by regulation or company culture), and your infrastructure. At a 
minimum you obviously need to persist your encryption keys somewhere safe,
separate from the data being encrypted. You also need to plan for key 
rotation, supporting multiple keys, with only the most recent being 
used to encrypt new data. Solutions such as 
[Azure Key Vault](https://azure.microsoft.com/en-us/services/key-vault/) 
can be used to store and rotate your keys. 

A simple implementation of a key ring is contained in 
[ProtectorAlgorithmHelper](AspNetCoreIdentityEncryption\KeyRing.cs). It
stores keys in a sub-folder of your application directory. If no key is 
present it will create one. It does not support key rotation or sharing
of keys between multiple applications like a real world implementation
would do, nor does it protect the keys at rest, they're sitting there 
in plain text.

You may have noticed that the key ring only gives you one key. When 
you are encrypting you will want multiple keys, one for encrypting, one for 
authenticated signing (because, of course, you won't store data without 
signing it, then validating the signature before attempting to decrypt).
So you are going to need to derive keys before you use them. We do that 
in our protector implementations.

### <a name="indexingProblem"></a> The problem with indexes

Encrypting data manually presents one key problem, that of indexing. 
As identity information needs to be retrieved often and decrypted quickly 
we are restricted to using symmetric encryption. Best practice dictates 
that every item of data uses a unique initialization vector, randomly 
generated, so that no inference can be made from the encrypted data. If,
for example, we used a fixed IV and encrypted a town name the result 
would be identical each time, and if your data were exposed you could 
mine the data to see how many people are in the same town, even though you 
don't have the encryption key. We use this approach in ASP.NET Core 
Data Protection, so that if you encrypt "Contoso" multiple times the result 
will be different on each occasion.

However this presents a problem with indexes. We want data used for lookup to
be deterministic, that is, when it is encrypted it has the same value each time,
but we also want some variance, we want a different IV for each record.

In order to do this we must derive the IV from the data itself. 
One approach to this is to take the results of a signed hashing algorithm 
like an HMAC over the data and use that as the IV into the symmetric encryption algorithm.
This approach in itself a drawback, if, for example, we were encrypting a City 
field an attacker who has the database contents could see which rows were 
referring to the same city, without knowing what the city itself is actually
encrypted as.

### Implementing a lookup protector

`ILookupProtector` has two methods:

```c#
public interface ILookupProtector
{
    string Protect(string keyId, string data);

    string Unprotect(string keyId, string data);
}
```

As you can see each method takes two parameters: a `keyId` and the data 
to be protected. Where does the `keyId` come from? Your key ring. When encrypting data
ASP.NET Core Identity will pass in the current key identifier, then prepend it to the data
returned from your `Protect` method. When it comes to decrypt data Identity will extract the 
key identifier from the cipher text and pass it into `Unprotect`.

The sample implementation of the [LookupProtector](AspNetCoreIdentityEncryption\LookupProtector.cs) 
implements signed encryption using derived keys, as well as solving the 
[indexing problem](#indexingProblem) by using the plain text as the IV. 

### Enabling index encryption in ASP.NET Core Identity

Now you have a key ring, and a protector, and obviously you've tested both, 
you need to enable encryption in ASP.NET Core Identity.

In `Startup.cs` look for the identity configuration code, 
the default code looks as follows:

```c#
services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Stores.MaxLengthForKeys = 128;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultUI()
.AddDefaultTokenProviders();
```

Change this to set `Stores.ProtectPersonalData` to true and to add 
your lookup protector and keyring implementations into DI;

```c#
services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Stores.ProtectPersonalData = true;
    options.Stores.MaxLengthForKeys = 128;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultUI()
.AddDefaultTokenProviders();

services.AddScoped<ILookupProtectorKeyRing, KeyRing>();
services.AddScoped<ILookupProtector, LookupProtector>();
```

What will happen now is the `UserStore` will use the lookup protector 
to protect the data it uses for lookups: `NormalizedUserName` and 
`NormalizedEmail`. All other data in your model is left untouched.

If you limit yourself to this approach using the default Entity Framework
based store and Identity User running will fail, due to a missing `IPersonalDataProtector`. 
This is what you must implement next.

### Encrypting non-indexed personal data

Encryption of non-indexed personal data relies on an Entity Framework Core
feature called value converters. These run before data is persisted and 
after data is retrieved. Implementation of this feature involves you
implementing an `IPersonalDataProtector`. This interface is exactly the same
as that for a `ILookupProtector`, however your implementation can produce
non-deterministic results, using random IVs, because this isn't used
for indexed data. A default implementation is in the framework, which 
uses whatever `ILookupProtector` you wire up, but this will then be 
deterministic and open to cipher text analysis so this may not meet the 
requirements your risk analysis or regulations require.

The sample [PersonalDataProtector](AspNetCoreIdentityEncryption\PersonalProtector.cs) 
avoids the cryptanalysis issue by ensuring data is encrypted with a random IV, it's basically
a clone of the `ILookupProtector` implementation with different derived keys, and no IV 
generation from source data. You will see that `IPersonalDataProtector` 
does not get key identifiers in protect and unprotect, because it doesn't
require a key ring. The sample implementation however uses the same 
keyring implementation as its source for keys and embeds the key identifier
in the encryption results, extracting it during decryption.

Once we have an implementation of [IPersonalDataProtector] we put it into DI:

```c#
services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Stores.ProtectPersonalData = true;
    options.Stores.MaxLengthForKeys = 128;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultUI()
.AddDefaultTokenProviders();

services.AddScoped<ILookupProtectorKeyRing, KeyRing>();
services.AddScoped<ILookupProtector, LookupProtector>();
services.AddScoped<IPersonalDataProtector, PersonalDataProtector>();
```

And we're done.

### Marking your EF model for encryption

ASP.NET Core Identity uses attributes to annotate your model and mark classes 
for encryption. We mark a few things in the default 
[IdentityUser](https://github.com/aspnet/Identity/blob/dev/src/Stores/IdentityUser.cs) class 
including the `Id`, `UserName`, `Email`, `PhoneNumber` and a couple of status fields.

To have Identity encrypt your custom `IdentityUser` model, annotate your model fields 
with `[ProtectedPersonalData]`.

## In Conclusion

Avoid manual encryption at all costs. It's risky and involves not only an 
understanding of the data loss risks, but also the ins and outs of cryptography.
Letting the database or OS do all the work is a much safer approach, but
the capability is there, should you really, truly, desperately need it.
Just remember your implementation is supported by you, not Microsoft.
