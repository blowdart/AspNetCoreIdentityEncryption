using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace AspNetCoreIdentityEncryptionTests
{
    public class PersonalDataProtectorTestsTests
    {
        [Fact]
        public void EncryptionOfALookupFieldIsNotDeterministic()
        {
            const string input = "bob@contoso.com";

            var keyRing = new KeyRing();
            var personalDataProtector = new AspNetCoreIdentityEncryption.PersonalDataProtector(keyRing);

            string output1 = personalDataProtector.Protect(input);
            string output2 = personalDataProtector.Protect(input);

            Assert.NotEqual(output1, output2);
        }

        [Fact]
        public void EncryptionTwoDifferentPlainTextsDoesNotProduceTheSameResult()
        {
            const string input1 = "bob@contoso.com";
            const string input2 = "alice@contoso.com";

            var keyRing = new KeyRing();
            var personalDataProtector = new AspNetCoreIdentityEncryption.PersonalDataProtector(keyRing);

            string output1 = personalDataProtector.Protect(input1);
            string output2 = personalDataProtector.Protect(input2);

            Assert.NotEqual(output1, output2);
        }

        [Fact]
        public void EncryptThenDecryptProducesPlainText()
        {
            const string input = "bob@contoso.com";

            var keyRing = new KeyRing();
            var keyId = keyRing.CurrentKeyId;
            var personalDataProtector = new AspNetCoreIdentityEncryption.PersonalDataProtector(keyRing);

            var cipherText = personalDataProtector.Protect(input);
            var plainText = personalDataProtector.Unprotect(cipherText);

            Assert.Equal(input, plainText);
        }

        [Fact]
        public void RoatingTheKeyRingDoesNotBreakDecryption()
        {
            const string input = "bob@contoso.com";

            var keyRing = new KeyRing();
            var keyId = keyRing.CurrentKeyId;
            var personalDataProtector = new AspNetCoreIdentityEncryption.PersonalDataProtector(keyRing);

            var cipherText = personalDataProtector.Protect(input);
            keyRing.CreateAndActivateNewKey();
            var plainText = personalDataProtector.Unprotect(cipherText);

            Assert.Equal(input, plainText);
        }

        class KeyRing : ILookupProtectorKeyRing
        {
            private readonly IDictionary<string, string> _keyDictionary = new Dictionary<string, string>();

            public KeyRing()
            {
                CreateAndActivateNewKey();
            }

            public string this[string keyId]
            {
                get
                {
                    return _keyDictionary[keyId];
                }
            }

            public string CurrentKeyId
            {
                get; private set;
            }

            public IEnumerable<string> GetAllKeyIds()
            {
                return _keyDictionary.Keys;
            }

            public void CreateAndActivateNewKey()
            {
                var keyId = Guid.NewGuid().ToString();
                var key = Aes.Create();
                var keyAsString = Convert.ToBase64String(key.Key);
                _keyDictionary.Add(keyId, keyAsString);
                CurrentKeyId = keyId;
            }
        }
    }
}
