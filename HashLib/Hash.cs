/* Copyright 2009 HPDI, LLC
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Security.Cryptography;

namespace Hpdi.HashLib
{
    /// <summary>
    /// Interface for 16-bit hash functions.
    /// </summary>
    /// <author>Trevor Robinson</author>
    public interface Hash16
    {
        ushort Compute(byte[] bytes);
        ushort Compute(byte[] bytes, int offset, int limit);
    }

    /// <summary>
    /// Interface for 32-bit hash functions.
    /// </summary>
    /// <author>Trevor Robinson</author>
    public interface Hash32
    {
        uint Compute(byte[] bytes);
        uint Compute(byte[] bytes, int offset, int limit);
    }

    /// <summary>
    /// 16-bit hash function based on XORing the upper and lower words of a 32-bit hash.
    /// </summary>
    /// <author>Trevor Robinson</author>
    public class XorHash32To16 : Hash16
    {
        private readonly Hash32 hash32;

        public XorHash32To16(Hash32 hash32)
        {
            this.hash32 = hash32;
        }

        public ushort Compute(byte[] bytes)
        {
            return Compute(bytes, 0, bytes.Length);
        }

        public ushort Compute(byte[] bytes, int offset, int limit)
        {
            uint value32 = hash32.Compute(bytes, offset, limit);
            return (ushort)(value32 ^ (value32 >> 16));
        }
    }

    public class Crc16Algorithm : HashAlgorithm
    {
        private Hash16 hash;
        private ushort result;

        public Crc16Algorithm(Hash16 hash)
        {
            this.hash = hash;
        }

        public override void Initialize()
        {
            result = 0x0;
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            result = hash.Compute(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(result);
        }
    }

    public class Crc32Algorithm : HashAlgorithm
    {
        private Hash32 hash;
        private uint result;

        public Crc32Algorithm(Hash32 hash)
        {
            this.hash = hash;
        }

        public override void Initialize()
        {
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            result = hash.Compute(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(result);
        }
    }

    public class Xor32To16AdapterAlgorithm : HashAlgorithm
    {
        private XorHash32To16 hash;
        private ushort result;

        public Xor32To16AdapterAlgorithm(XorHash32To16 hash)
        {
            this.hash = hash;
        }

        public override void Initialize()
        {
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            result = hash.Compute(array, ibStart, cbSize);
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(result);
        }
    }

    public class Xor32To16Algorithm : HashAlgorithm
    {
        private HashAlgorithm hash;
        private ushort result;

        public Xor32To16Algorithm(HashAlgorithm hash)
        {
            this.hash = hash;
        }

        public override void Initialize()
        {
            hash.Initialize();
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            if (hash.HashSize > (sizeof(uint) * 8))
                throw new InvalidOperationException("The hash length is incoherent. Should be 32 bits.");

            uint v = BitConverter.ToUInt32(hash.ComputeHash(array, ibStart, cbSize), 0);
            result = (ushort)(v ^ (v >> 16));
        }

        protected override byte[] HashFinal()
        {
            return BitConverter.GetBytes(result);
        }
    }
}
