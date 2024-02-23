Imports System.IO
Imports System.Security.Cryptography

Public Class clsCrypto

    Private Shared mutf8enc As System.Text.UTF8Encoding
    Private Shared micryptoEncryptor As ICryptoTransform
    Private Shared micryptoDecryptor As ICryptoTransform
    
    Private Shared Sub Initialize_AES_Cipher()

        Dim byteKey As Byte() = {42, 1, 52, 67, 231, 13, 94, 101, 123, 6, 0, 12, 32, 91, 4, 111, 31, 70, 21, 141, 123, 142, 234, 82, 95, 129, 187, 162, 12, 55, 98, 23}
        Dim byteIV As Byte() = {234, 12, 52, 44, 214, 222, 200, 109, 2, 98, 45, 76, 88, 53, 23, 78}

        Try
            mutf8enc = New System.Text.UTF8Encoding
            Using aesAlgorithm As Aes = Aes.Create()
                micryptoEncryptor = aesAlgorithm.CreateEncryptor(byteKey, byteIV)
                micryptoDecryptor = aesAlgorithm.CreateDecryptor(byteKey, byteIV)
            End Using
        Catch ex As Exception
            Throw ex
        End Try

    End Sub
    Public Shared Function AES_Encrypt(ByVal strPlainText As String) As String

        If String.IsNullOrWhiteSpace(strPlainText) Or Len(strPlainText) = 0 Then Exit Function

        Dim byteEncryptedText As Byte()

        Try
            Initialize_AES_Cipher()
            Using mstrmEncrypt As MemoryStream = New MemoryStream()
                Using cstrmEncrypt As CryptoStream = New CryptoStream(mstrmEncrypt, micryptoEncryptor, CryptoStreamMode.Write)
                    Using swEncrypt As New StreamWriter(cstrmEncrypt)
                        swEncrypt.Write(strPlainText)
                    End Using
                End Using
                byteEncryptedText = mstrmEncrypt.ToArray()
            End Using
        Catch ex As Exception
            Throw ex
        Finally
            AES_Encrypt = Convert.ToBase64String(byteEncryptedText)
        End Try

    End Function
    Public Shared Function AES_Decrypt(ByVal strEncryptedText As String) As String

        If String.IsNullOrWhiteSpace(strEncryptedText) Or Len(strEncryptedText) = 0 Then Exit Function

        Dim strPlainText As String

        Try
            Initialize_AES_Cipher()
            Dim byteEncryptedText As Byte() = Convert.FromBase64String(strEncryptedText)
            Using mstrmDecrypt As MemoryStream = New MemoryStream(byteEncryptedText)
                Using cstrmDecrypt As CryptoStream = New CryptoStream(mstrmDecrypt, micryptoDecryptor, CryptoStreamMode.Read)
                    Using srDecrypt As New StreamReader(cstrmDecrypt)
                        strPlainText = srDecrypt.ReadToEnd()
                    End Using
                End Using
            End Using
        Catch ex As Exception
            Throw ex
        Finally
            AES_Decrypt = strPlainText
        End Try

    End Function
    Private Shared Sub Initialize_Rijndael_Cipher()

        Dim KEY_128 As Byte() = {42, 1, 52, 67, 231, 13, 94, 101, 123, 6, 0, 12, 32, 91, 4, 111, 31, 70, 21, 141, 123, 142, 234, 82, 95, 129, 187, 162, 12, 55, 98, 23}
        Dim IV_128 As Byte() = {234, 12, 52, 44, 214, 222, 200, 109, 2, 98, 45, 76, 88, 53, 23, 78}

        Try
            mutf8enc = New System.Text.UTF8Encoding
            Using symmetricKey As RijndaelManaged = New RijndaelManaged()
                symmetricKey.Mode = CipherMode.CBC
                micryptoEncryptor = symmetricKey.CreateEncryptor(KEY_128, IV_128)
                micryptoDecryptor = symmetricKey.CreateDecryptor(KEY_128, IV_128)
            End Using
        Catch ex As Exception
            Throw ex
        End Try

    End Sub
    Public Shared Function Rijndael_Encrypt(strPlainText As String) As String

        If String.IsNullOrWhiteSpace(strPlainText) Or Len(strPlainText) = 0 Then Exit Function

        Dim strEncryptedText As String

        Try
            Initialize_Rijndael_Cipher()
            Using mstrmEncrypt As MemoryStream = New MemoryStream()
                Using cstrmEncrypt As CryptoStream = New CryptoStream(mstrmEncrypt, micryptoEncryptor, CryptoStreamMode.Write)
                    cstrmEncrypt.Write(mutf8enc.GetBytes(strPlainText), 0, strPlainText.Length)
                    cstrmEncrypt.FlushFinalBlock()
                End Using
                strEncryptedText = Convert.ToBase64String(mstrmEncrypt.ToArray())
            End Using
        Catch ex As Exception
            Throw ex
        Finally
            Rijndael_Encrypt = strEncryptedText
        End Try

    End Function
    Public Shared Function Rijndael_Decrypt(strEncryptedText As String) As String

        If String.IsNullOrWhiteSpace(strEncryptedText) Or Len(strEncryptedText) = 0 Then Exit Function

        Dim strPlainText As String

        Try
            Initialize_Rijndael_Cipher()
            Dim byteEncryptedText As Byte() = Convert.FromBase64String(strEncryptedText)
            Dim bytePlainText(byteEncryptedText.Length) As Byte
            Using mstrmDecrypt As MemoryStream = New MemoryStream(byteEncryptedText)
                Using cstrmDecrypt As CryptoStream = New CryptoStream(mstrmDecrypt, micryptoDecryptor, CryptoStreamMode.Read)
                    Dim intDecryptedByteCount As Integer = cstrmDecrypt.Read(bytePlainText, 0, bytePlainText.Length)
                    strPlainText = mutf8enc.GetString(bytePlainText, 0, intDecryptedByteCount)
                End Using
            End Using
        Catch ex As Exception
            Throw ex
        Finally
            Rijndael_Decrypt = strPlainText
        End Try

    End Function

End Class
