// The text encryption program in C++ and ASM with a very simple example encryption method - it simply adds 1 to the character.
// The encryption method is written in ASM. You will replace this with your allocated version for the assignment.
// In this version parameters are passed via registers (see 'encrypt' for details).
//
// Original Author: A.Oram - 2012
// Last revised: J.Mogg-Wright - March 2022


#include <string>     // for std::string
#include <chrono>     // for date & time functions
#include <ctime>      // for date & time string functions
#include <iostream>   // for std::cout <<
#include <fstream>    // for file I/O
#include <iomanip>    // for fancy output
#include <functional> // for std::reference_wrapper
#include <vector>     // for std::vector container


constexpr char const * STUDENT_NAME = "Jaike Mogg-Wright";
constexpr int ENCRYPTION_ROUTINE_ID = 9;                
constexpr char ENCRYPTION_KEY = 't';
constexpr int MAX_CHARS = 6;

constexpr char STRING_TERMINATOR = '$';
constexpr char LINE_FEED_CHARACTER = '\n';
constexpr char CARRIAGE_RETURN_CHARACTER = '\r';

char original_chars[MAX_CHARS];                              // Original character string
char encrypted_chars[MAX_CHARS];                             // Encrypted character string
char decrypted_chars[MAX_CHARS];                            // Decrypted character string


//---------------------------------------------------------------------------------------------------------------
//----------------- C++ FUNCTIONS -------------------------------------------------------------------------------

/// <summary>
/// get a single character from the user via Windows function _getwche
/// </summary>
/// <param name="a_character">the resultant character, pass by reference</param>
void get_char (char& a_character)
{
  a_character = (char)_getwche (); // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/getche-getwche

  if (a_character == STRING_TERMINATOR) // skip further checks if user entered string terminating character
  {
    return;
  }
  if (a_character == LINE_FEED_CHARACTER || a_character == CARRIAGE_RETURN_CHARACTER)  // treat all 'new line' characters as terminating character
  {
    a_character = STRING_TERMINATOR;
    return;
  }
}

//---------------------------------------------------------------------------------------------------------------
//----------------- ENCRYPTION ROUTINE --------------------------------------------------------------------------

/// <summary>
/// 'encrypt' the characters in original_chars, up to length
/// output 'encrypted' characters in to encrypted_chars
/// </summary>
/// <param name="length">length of string to encrypt, pass by value</param>
/// <param name="EKey">encryption key to use during encryption, pass by value</param>
void __cdecl encrypt_chars (int length, char EKey)
{
  char temp_char;                      // Temporary character store

  for (int i = 0; i < length; ++i)     // Encrypt characters one at a time
  {
    temp_char = original_chars [i];    // Get the next char from original_chars array
                                       // Note the lamentable lack of comments below!
    __asm
    {
        push   eax                     // Copy the value of eax to stack, freeing that register for use
        push   ecx                     // Copy the value of ecx to stack, freeing that register for use
        push   edx                     // Copy the value of edx to stack, freeing that register for use
        lea    eax, EKey               /// [PARAMETER PASS] Load effective address of variable 'EKey' (the encryption key) into register eax
        push   eax                     // and then push eax onto the stack
        movzx  ecx, temp_char          /// [PARAMETER PASS] Move temporary character (character to be encrypted) to register ecx with zero extension
        push   ecx                     // and then push ecx onto the stack

        call   encrypt_9               // Call subroutine 'encrypt_9'
        add    esp, 8                  // Scrubbing Parameters from the stack by moving stack pointer up by 8
        mov    temp_char, al           // [RETURN VALUE] Move into temp_char the encrypted character returned from subroutine 'encrypt_9'
      
        pop    edx                     // Remove, from the stack, the value of edx back into edx
        pop    ecx                     // Remove, from the stack, the value of ecx back into ecx
        pop    eax                     // Remove, from the stack, the value of eax back into eax
    }

    encrypted_chars [i] = temp_char; // Store encrypted char in the encrypted_chars array
  }

  return;

  // Inputs: register EAX = 32-bit address of Ekey
  //                  ECX = the character to be encrypted (in the low 8-bit field, CL)
  // Output: register EDX = the encrypted value of the source character (in the low 8-bit field, DL)

  __asm
  {
  encrypt_9:
      push      ebp                 //Save the old base pointer
      mov       ebp, esp            //and make a new one at the current stack pointer - new stack frame for this subroutine!

      push      ebx                 //Save the original state of this register to stack (we have use of your boundiful bytes)

      mov       ecx, [ebp + 08h]    //Value of our passed character to encrypt (temp_char) -
      push      ecx                 //and onto the stack with you!

      mov       eax, [ebp + 0Ch]    //Address of our passed encryption key (EKey)

      mov       ebx, [eax]          //Put the value of our encryption key (resolved from the address we put in 'eax') into 'ebx'
      and       ebx, 0x000000FF     //then make sure that it's only occupying the least sig. byte (so basically that it's a char)

      mov       edx, 05             //Prepare to scramble the key - we're going to roll five times and 'edx' will keep track

  //Here, we will scramble the key
  x9 : rol   bl, 1          //Roll the least sig. byte of ebx by 1 (bits are shifted to the left by one place and around to the least sig. bit, like a carousel)
      dec       edx           /// ...decrement edx...
      jnz       x9            /// ...and jump to x9 if edx is not zero.

      or        ebx, 04h    //Verify that ebx still contains data only within the least sig. byte

      mov       edx, ebx    //Copy the now scrambled key into edx (we'll use this as the iterator to encrypt the actual character)
      mov       [eax], ebx  //and also into the address within 'eax' the scrambled key (ensures no two identical characters can be the same when encrypted)
     
      pop       eax         //Remove from the stack the original character to be encrypted and put it into 'eax' (since we don't need the address of the key anymore)

  //Here, we will encrypt the character
  y9 : rol   al, 1        //Roll the least sig. byte of eax by 1 (bits are shifted to the left by one placeand around to the least sig. bit, like a carousel)
      dec       edx           /// ...decrememnt edx...
      jnz       y9            /// ...and jump to y9 if edx is not zero.
              

      pop       ebx       //Restore ebx to pre-call state from the stack (thank you for your bytes)

      mov       esp, ebp  //Discard the current stack frame by setting the stack pointer to the base pointer of this grame
      pop       ebp       //Restore the base pointer of the previous stack from the stack
      ret                 //Return to caller
  }
}
//*** end of encrypt_chars function
//---------------------------------------------------------------------------------------------------------------

//---------------------------------------------------------------------------------------------------------------
//----------------- DECRYPTION ROUTINE --------------------------------------------------------------------------

/// <summary>
/// 'decrypt' the characters in encrypted_chars, up to length
/// output 'decrypted' characters in to decrypted_chars
/// </summary>
/// <param name="length">length of string to decrypt, pass by value</param>
/// <param name="EKey">encryption key to used during the encryption process, pass by value</param>
void decrypt_chars (int length, char EKey)
{
    char temp_char;

    for (int i = 0; i < length; ++i)
    {
        temp_char = encrypted_chars[i];

        __asm
        {
            push    eax             //Save registers to the stack (we need to use these spots),
            push    ecx             //with 'eax' at the bottom
            push    edx             //and 'edx' at the top - we'll remember this for when we put them back

            lea     eax, EKey       //Get the address of our passed encryption key and put it in 'eax'
            push    eax             //and then put that on the stack

            movzx   ecx, temp_char  //Move into 'ecx' our passed character to decrypt (with an extension of zeros for the rest of the register that we don't care about) 
            push    ecx             //and then put that on the stack

            call    decrypt         //DECRYPT THE CHAR

            add     esp, 8          //Discard the parameters we put on the stack by shrinking it - we don't need them anymore
            mov     temp_char, al   //Move the decrypted char from our return register (actually 'eax' but we only want the least sig. byte so 'al')

            pop     edx             //Put all the registers back how they were before
            pop     ecx             //in reverse order of how we put them on the stack to begin with - 
            pop     eax             //with 'edx' being the last in, so first out, and so on.
        }
    }

    decrypted_chars[i] = temp_char;

    return;

    __asm
    {
    decrypt:
        push    ebp                 //Save the old base pointer
        mov     ebp, esp            //and make a new one at the current stack pointer - new stack frame for this subroutine!

        push    ebx                 //Save the original state of this register to stack (we have use of your boundiful bytes)

        mov     ecx, [ebp+08h]      //Value of our passed character to decrypt (temp_char) -
        push    ecx                 //and onto the stack with you!

        mov     eax, [ebp+0Ch]      //Address of our passed encryption key (EKey)

        mov     ebx, [eax]          //Put the value of our encryption key (resolved from the address we put in 'eax') into 'ebx'
        and     ebx, 0x000000FF     //then make sure that it's only occupying the least sig. byte (so basically that it's a char)

        mov     edx, 05             //Prepare to decrypt - we're going to roll five times and 'edx' will keep track

        //
        /*decrypt thingy*/
        //

        pop       ebx               //Restore ebx to pre-call state from the stack (thank you for your bytes)

        mov       esp, ebp          //Discard the current stack frame by setting the stack pointer to the base pointer of this grame
        pop       ebp               //Restore the base pointer of the previous stack from the stack
        ret                         //Return to caller
    }
}
//*** end of decrypt_chars function
//---------------------------------------------------------------------------------------------------------------





//************ MAIN *********************************************************************************************
//************ YOU DO NOT NEED TO EDIT ANYTHING BELOW THIS LINE *************************************************
//************ BUT FEEL FREE TO HAVE A LOOK *********************************************************************

void get_original_chars (int& length)
{
  length = 0;

  char next_char;
  do
  {
    next_char = 0;
    get_char (next_char);
    if (next_char != STRING_TERMINATOR)
    {
      original_chars [length++] = next_char;
    }
  }
  while ((length < MAX_CHARS) && (next_char != STRING_TERMINATOR));
}

std::string get_date ()
{
  std::time_t now = std::chrono::system_clock::to_time_t (std::chrono::system_clock::now ());
  char buf[16] = { 0 };
  tm time_data;
  localtime_s (&time_data, &now);
  std::strftime (buf, sizeof(buf), "%d/%m/%Y", &time_data);
  return std::string{ buf };
}

std::string get_time ()
{
  std::time_t now = std::chrono::system_clock::to_time_t (std::chrono::system_clock::now ());
  char buf[16] = { 0 };
  tm time_data;
  localtime_s (&time_data, &now);
  std::strftime (buf, sizeof (buf), "%H:%M:%S", &time_data);
  return std::string{ buf };
}

// support class to help output to multiple streams at the same time
struct multi_outstream
{
  void add_stream (std::ostream& stream)
  {
    streams.push_back (stream);
  }

  template <class T>
  multi_outstream& operator<<(const T& data)
  {
    for (auto& stream : streams)
    {
      stream.get () << data;
    }
    return *this;
  }

private:
  std::vector <std::reference_wrapper <std::ostream>> streams;
};

int main ()
{
  int char_count = 0;  // The number of actual characters entered (upto MAX_CHARS limit)

  std::cout << "Please enter upto " << MAX_CHARS << " alphabetic characters: ";
  get_original_chars (char_count);	// Input the character string to be encrypted


  //*****************************************************
  // Open a file to store results (you can view and edit this file in Visual Studio)

  std::ofstream file_stream;
  file_stream.open ("log.txt", std::ios::app);
  file_stream << "Date: " << get_date () << " Time: " << get_time () << "\n";
  file_stream << "Name:                  " << STUDENT_NAME << "\n";
  file_stream << "Encryption Routine ID: '" << ENCRYPTION_ROUTINE_ID << "'" << "\n";
  file_stream << "Encryption Key:        '" << ENCRYPTION_KEY;

  multi_outstream output;
  output.add_stream (file_stream);
  output.add_stream (std::cout);


  //*****************************************************
  // Display and save to the log file the string just input

  output << "\n\nOriginal string  = ";
  output << std::right << std::setw (MAX_CHARS) << std::setfill (' ') << original_chars;

  // output each original char's hex value
  output << " Hex = ";
  for (int i = 0; i < char_count; ++i)
  {
    int const original_char = static_cast <int> (original_chars [i]) & 0xFF; // ANDing with 0xFF prevents static_cast padding 8 bit value with 1s
    output << std::hex << std::right << std::setw (2) << std::setfill ('0') << original_char << " ";
  }


  //*****************************************************
  // Encrypt the string and display/save the result

  encrypt_chars (char_count, ENCRYPTION_KEY);

  output << "\n\nEncrypted string = ";
  output << std::right << std::setw (MAX_CHARS) << std::setfill (' ') << encrypted_chars;

  // output each encrypted char's hex value
  output << " Hex = ";
  for (int i = 0; i < char_count; ++i)
  {
    int const encrypted_char = static_cast <int> (encrypted_chars [i]) & 0xFF; // ANDing with 0xFF prevents static_cast padding 8 bit value with 1s
    output << std::hex << std::right << std::setw (2) << std::setfill ('0') << encrypted_char << " ";
  }


  //*****************************************************
  // Decrypt the encrypted string and display/save the result

  decrypt_chars (char_count, ENCRYPTION_KEY);

  output << "\n\nDecrypted string = ";
  output << std::right << std::setw (MAX_CHARS) << std::setfill (' ') << decrypted_chars;

  // output each decrypted char's hex value
  output << " Hex = ";
  for (int i = 0; i < char_count; ++i)
  {
    int const decrypted_char = static_cast <int> (decrypted_chars [i]) & 0xFF; // ANDing with 0xFF prevents static_cast padding 8 bit value with 1s
    output << std::hex << std::right << std::setw (2) << std::setfill ('0') << decrypted_char << " ";
  }


  //*****************************************************
  // End program

  output << "\n\n";
  file_stream << "-------------------------------------------------------------\n\n";
  file_stream.close ();

  system ("PAUSE"); // do not use in your other programs! just a hack to pause the program before exiting

  return 0;
}

//**************************************************************************************************************
