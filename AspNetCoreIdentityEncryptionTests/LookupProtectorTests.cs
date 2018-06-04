using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace AspNetCoreIdentityEncryptionTests
{
    public class LookupProtectorTests
    {
        [Fact]
        public void EncryptionOfALookupFieldIsDeterministic()
        {
            const string input = "bob@contoso.com";

            var keyRing = new KeyRing();
            var lookupProtector = new AspNetCoreIdentityEncryption.LookupProtector(keyRing);

            string output1 = lookupProtector.Protect(keyRing.CurrentKeyId, input);
            string output2 = lookupProtector.Protect(keyRing.CurrentKeyId, input);

            Assert.Equal(output1, output2);
        }

        [Fact]
        public void EncryptionTwoDifferentPlainTextsDoesNotProduceTheSameResult()
        {
            const string input1 = "bob@contoso.com";
            const string input2 = "alice@contoso.com";

            var keyRing = new KeyRing();
            var lookupProtector = new AspNetCoreIdentityEncryption.LookupProtector(keyRing);

            string output1 = lookupProtector.Protect(keyRing.CurrentKeyId, input1);
            string output2 = lookupProtector.Protect(keyRing.CurrentKeyId, input2);

            Assert.NotEqual(output1, output2);
        }

        [Fact]
        public void EncryptThenDecryptProducesPlainText()
        {
            const string input = "bob@contoso.com";

            var keyRing = new KeyRing();
            var keyId = keyRing.CurrentKeyId;
            var lookupProtector = new AspNetCoreIdentityEncryption.LookupProtector(keyRing);

            var cipherText = lookupProtector.Protect(keyId, input);
            var plainText = lookupProtector.Unprotect(keyId, cipherText);

            Assert.Equal(input, plainText);
        }

        [Fact]
        public void RoatingTheKeyRingDoesNotBreakDecryption()
        {
            const string input = "bob@contoso.com";

            var keyRing = new KeyRing();
            var keyId = keyRing.CurrentKeyId;
            var lookupProtector = new AspNetCoreIdentityEncryption.LookupProtector(keyRing);

            var cipherText = lookupProtector.Protect(keyId, input);
            keyRing.CreateAndActivateNewKey();
            var plainText = lookupProtector.Unprotect(keyId, cipherText);

            Assert.Equal(input, plainText);
        }

        [Fact]
        public void RoatingTheKeyRingProducesDifferentResultsFromEncryption()
        {
            const string input = "bob@contoso.com";

            var keyRing = new KeyRing();
            var lookupProtector = new AspNetCoreIdentityEncryption.LookupProtector(keyRing);

            var keyId = keyRing.CurrentKeyId;
            var result1 = lookupProtector.Protect(keyId, input);
            keyRing.CreateAndActivateNewKey();
            var newKeyId = keyRing.CurrentKeyId;
            var result2 = lookupProtector.Protect(newKeyId, input);

            Assert.NotEqual(result1, result2);
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
