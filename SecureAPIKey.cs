#region License
/*
VPKSoft.TMDbFileUtils

A class library to be used for scrambling mostly REST service API keys.
Copyright © 2018 VPKSoft, Petteri Kautonen

Contact: vpksoft@vpksoft.net

This file is part of VPKSoft.TMDbFileUtils.

VPKSoft.TMDbFileUtils is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

VPKSoft.TMDbFileUtils is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with VPKSoft.TMDbFileUtils.  If not, see <http://www.gnu.org/licenses/>.
*/
#endregion

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

#pragma warning disable CS1587 // XML comment is not placed on a valid language element
                              /// <summary>
                              /// A name space for the ScrambleAPIKey class.
                              /// </summary>
namespace VPKSoft.SecureAPIKey
#pragma warning restore CS1587 // XML comment is not placed on a valid language element
{
    /// <summary>
    /// This class is to be used for scrambling mostly REST service API keys.
    /// <note type="note">This is not an encryption library.</note>
    /// </summary>
    public static class ScrambleAPIKey
    {
        // initialize a static random number generator..
        private static Random random = new Random();

        /// <summary>
        /// Gets or sets the encoding to be used with the characters.
        /// </summary>
        public static Encoding Encoding { get; set; } = Encoding.Unicode;

        /// <summary>
        /// Gets or sets a string which characters are used to randomize variable length strings.
        /// </summary>
        public static string RandomFromString { get; set; } = "ABCDEFGHIJKLMNOPQRSTUVWXYZÅÄÖabcdefghijklmnopqrstuvwxyzåäö£€%[]$@ÂÊÎÔÛâêîôûÄËÏÖÜäëïöüÀÈÌÒÙàèìòùÁÉÍÓÚáéíóúÃÕãõ '|?+\\/{}½§01234567890+<>_-:;*&¤#\"!";

        /// <summary>
        /// A class to help random character positions of a string.
        /// </summary>
        private class CharIntPair
        {
            /// <summary>
            /// Gets or sets a character.
            /// </summary>
            public char Char { get; set; }

            /// <summary>
            /// Gets or sets a position of a character in a string.
            /// </summary>
            public int Position { get; set; }

            /// <summary>
            /// Randomizes a string's characters to random positions.
            /// </summary>
            /// <param name="value">The string value to randomize into a CharIntPair collection.</param>
            /// <returns>A collection of CharIntPair values where the characters positions in the string are randomized.</returns>
            public static IEnumerable<CharIntPair> Scramble(string value)
            {
                // initialize the return value
                List<CharIntPair> scrambled = new List<CharIntPair>();

                // loop while all character positions are randomized to unique positions..
                while (value.Length > scrambled.Count)
                {
                    // the initial random number..
                    int iPos = random.Next(value.Length);

                    // if the initial random number is being used then keep on randomizing 
                    // until the random value is unique..
                    while (scrambled.Exists(f => f.Position == iPos))
                    {
                        // ..so random..
                        iPos = random.Next(value.Length);
                    }

                    // get the character at the position..
                    char chr = value[iPos];

                    // add a new CharIntPair instance to the result..
                    scrambled.Add(new CharIntPair { Char = chr, Position = iPos });
                }
                return scrambled; // return the result..
            }

            /// <summary>
            /// Unscrambles the given list of CharIntPair class instances with their random positions.
            /// </summary>
            /// <param name="pairs">A collection of CharIntPair class instances to unscramble.</param>
            /// <returns>A string unscrambled from the CharIntPair list.</returns>
            public static string Unscramble(List<CharIntPair> pairs)
            {
                // just sort the given collection by character's position in a string..
                pairs = pairs.OrderBy(f => f.Position).ToList();

                // initialize the result string..
                string result = string.Empty;

                // loop through the sorted collection..
                for (int i = 0; i < pairs.Count; i++)
                {
                    // add a character to the result..
                    result += pairs[i].Char;
                }
                return result; // return the result..
            }
        }

        /// <summary>
        /// "Secures" the given API key.
        /// </summary>
        /// <param name="apiKey">The API key to "secure".</param>
        /// <param name="randomNoiseMin">The minimum value of the random noise (random characters) to be added to the return value.</param>
        /// <param name="randomNoiseMax">The maximum value of the random noise (random characters) to be added to the return value.</param>
        /// <returns></returns>
        public static string Secure(string apiKey, int randomNoiseMin = 30, int randomNoiseMax = 90)
        {
            // random characters to the beginning oh the string..
            byte[] randomNoise1 = Encoding.GetBytes(RandomString(random.Next(randomNoiseMin, randomNoiseMax)));

            // random characters to the end of the string..
            byte[] randomNoise2 = Encoding.GetBytes(RandomString(random.Next(randomNoiseMin, randomNoiseMax)));

            // the API key to scramble..
            byte[] apiKeyBytes = Encoding.GetBytes(apiKey);

            // scramble the API key..
            List<CharIntPair> scrambled = CharIntPair.Scramble(apiKey).ToList();

            byte[] scramble; // the return value..
            using (MemoryStream ms = new MemoryStream()) // IDisposable, so using..
            {
                using (BinaryWriter bw = new BinaryWriter(ms)) // IDisposable, so using..
                {
                    bw.Write(randomNoise1.Length); // write the randomized start string's length..
                    bw.Write(randomNoise1); // write the randomized start string..

                    // write the amount of scrambled API key characters and their positions..
                    bw.Write(scrambled.Count);

                    // write the scrambled API key characters and their positions..
                    foreach (CharIntPair pair in scrambled)
                    {
                        bw.Write(pair.Position);
                        bw.Write(pair.Char);
                    }

                    bw.Write(randomNoise2.Length); // write the randomized end string's length..
                    bw.Write(randomNoise2); // write the randomized end string..
                }
                scramble = ms.ToArray(); // set the return value..
            }
            // return the value as Base64 encoded string..
            return Convert.ToBase64String(scramble);
        }

        /// <summary>
        /// Returns the plain text of the "secured" string value.
        /// </summary>
        /// <param name="value">The "secured" value to unscramble.</param>
        /// <returns>The plain text of the "secured" string value.</returns>
        public static string Unsecure(string value)
        {
            // get the bytes from a Base64 encoded string..
            byte[] scrambled = Convert.FromBase64String(value);

            // create a list of CharIntPair class instances to read the API key into..
            List<CharIntPair> pairs = new List<CharIntPair>();
            using (MemoryStream ms = new MemoryStream(scrambled)) // IDisposable, so using..
            {
                using (BinaryReader br = new BinaryReader(ms)) // IDisposable, so using..
                {
                    int len = br.ReadInt32(); // read the length of randomized noise from the stream..
                    br.ReadBytes(len); // read the randomized noise from the stream..
                    len = br.ReadInt32(); // read the amount of CharIntPair values stored in the stream..
                    for (int i = 0; i < len; i++) // go through the CharIntPair values in the stream..
                    {
                        // add the read pair to the list..
                        pairs.Add(new CharIntPair() { Position = br.ReadInt32(), Char = br.ReadChar() });
                    }
                    // unscramble and return the "unsecured" string value..
                    return CharIntPair.Unscramble(pairs);

                    // PS. the randomized end noise is not to be concerned about..
                }
            }
        }

        /// <summary>
        /// Randomizes a string with the length of <paramref name="length"/> with randomized characters.
        /// </summary>
        /// <param name="length">The length of the string to randomize.</param>
        /// <returns>A string with the length of <paramref name="length"/> with randomized characters.</returns>
        public static string RandomString(int length)
        {
            string result = string.Empty; // initialize the result..
            for (int i = 0; i < length; i++) // random characters with the given length..
            {
                // add a random character to the result..
                result += RandomFromString[random.Next(RandomFromString.Length)];
            }
            return result; // return the result..
        }
    }
}
