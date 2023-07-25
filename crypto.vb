Imports System.IO
Imports System.Security.Cryptography

Module Crypto

    Public enc As System.Text.UTF8Encoding
    Public encryptor As ICryptoTransform
    Public decryptor As ICryptoTransform
    
    Public Sub Initialize()

        Dim KEY_128 As Byte() = {42, 1, 52, 67, 231, 13, 94, 101, 123, 6, 0, 12, 32, 91, 4, 111, 31, 70, 21, 141, 123, 142, 234, 82, 95, 129, 187, 162, 12, 55, 98, 23}
        Dim IV_128 As Byte() = {234, 12, 52, 44, 214, 222, 200, 109, 2, 98, 45, 76, 88, 53, 23, 78}
        Dim symmetricKey As RijndaelManaged = New RijndaelManaged()

        symmetricKey.Mode = CipherMode.CBC
        enc = New System.Text.UTF8Encoding
        encryptor = symmetricKey.CreateEncryptor(KEY_128, IV_128)
        decryptor = symmetricKey.CreateDecryptor(KEY_128, IV_128)

    End Sub
    
    Public Function Encrypt(strPlainText As String) As String

        If String.IsNullOrEmpty(strPlainText) Then Exit Function

        Initialize()

        Dim memoryStream As MemoryStream = New MemoryStream()
        Dim cryptoStream As CryptoStream = New CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)
        Dim strEncryptedText As String

        cryptoStream.Write(enc.GetBytes(strPlainText), 0, strPlainText.Length)
        cryptoStream.FlushFinalBlock()

        strEncryptedText = Convert.ToBase64String(memoryStream.ToArray())

        memoryStream.Close()

        cryptoStream.Close()

        Encrypt = strEncryptedText

    End Function
    
    Public Function Decrypt(strEncryptedText As String) As String

        If String.IsNullOrEmpty(strEncryptedText) Then Exit Function

        Initialize()

        Dim cypherTextBytes As Byte() = Convert.FromBase64String(strEncryptedText)
        Dim memoryStream As MemoryStream = New MemoryStream(cypherTextBytes)
        Dim cryptoStream As CryptoStream = New CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read)
        Dim plainTextBytes(cypherTextBytes.Length) As Byte
        Dim decryptedByteCount As Integer = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length)
        Dim strPlainText As String

        memoryStream.Close()

        cryptoStream.Close()

        strPlainText = enc.GetString(plainTextBytes, 0, decryptedByteCount)

        Decrypt = strPlainText

    End Function

End Module