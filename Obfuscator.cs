using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.MSBuild;

namespace Obfuscator
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("C# DLL Obfuscator");
            Console.WriteLine("Usage: Obfuscator <path-to-dll-file>");
            
            if (args.Length == 0)
            {
                Console.WriteLine("Error: No file path provided.");
                return;
            }

            string filePath = args[0];
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"Error: File not found: {filePath}");
                return;
            }

            try
            {
                // Decompile the DLL
                var decompiler = new CSharpDecompiler(filePath, new DecompilerSettings());
                string code = decompiler.DecompileWholeModuleAsString();

                // Parse the decompiled code
                SyntaxTree tree = CSharpSyntaxTree.ParseText(code);
                CompilationUnitSyntax root = tree.GetCompilationUnitRoot();

                // Obfuscate the code
                var rewriter = new ObfuscatingRewriter();
                SyntaxNode newRoot = rewriter.Visit(root);

                // Write the obfuscated code to a temporary file
                string tempFilePath = Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(filePath) + "_obfuscated.cs");
                File.WriteAllText(tempFilePath, newRoot.ToFullString());

                // Compile the obfuscated code back into a DLL
                CompileObfuscatedCode(tempFilePath, filePath);

                Console.WriteLine("Obfuscation completed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        static void CompileObfuscatedCode(string sourceFilePath, string originalDllPath)
        {
            var workspace = MSBuildWorkspace.Create();
            var project = workspace.AddProject("ObfuscatedProject", LanguageNames.CSharp);
            var document = workspace.AddDocument(project.Id, Path.GetFileName(sourceFilePath), File.ReadAllText(sourceFilePath));

            var compilation = document.Project.GetCompilationAsync().Result;
            var assemblyPath = Path.Combine(Path.GetDirectoryName(originalDllPath), Path.GetFileNameWithoutExtension(originalDllPath) + "_obfuscated.dll");

            var emitResult = compilation.Emit(assemblyPath);
            if (!emitResult.Success)
            {
                foreach (var diagnostic in emitResult.Diagnostics)
                {
                    Console.WriteLine(diagnostic.ToString());
                }
                throw new Exception("Compilation failed.");
            }
        }
    }

    class ObfuscatingRewriter : CSharpSyntaxRewriter
    {
        private readonly Dictionary<string, string> _renamedIdentifiers = new Dictionary<string, string>();
        private readonly Random _random = new Random();
        private readonly Aes _aes;

        public ObfuscatingRewriter()
        {
            _aes = Aes.Create();
            _aes.GenerateKey();
            _aes.GenerateIV();
        }

        public override SyntaxNode VisitVariableDeclarator(VariableDeclaratorSyntax node)
        {
            string originalName = node.Identifier.Text;
            if (!_renamedIdentifiers.ContainsKey(originalName))
            {
                string newName = GenerateRandomString();
                _renamedIdentifiers[originalName] = newName;
            }

            return node.WithIdentifier(SyntaxFactory.Identifier(_renamedIdentifiers[originalName]));
        }

        public override SyntaxNode VisitMethodDeclaration(MethodDeclarationSyntax node)
        {
            string originalName = node.Identifier.Text;
            if (!_renamedIdentifiers.ContainsKey(originalName))
            {
                string newName = GenerateRandomString();
                _renamedIdentifiers[originalName] = newName;
            }

            return node.WithIdentifier(SyntaxFactory.Identifier(_renamedIdentifiers[originalName]));
        }

        public override SyntaxNode VisitClassDeclaration(ClassDeclarationSyntax node)
        {
            string originalName = node.Identifier.Text;
            if (!_renamedIdentifiers.ContainsKey(originalName))
            {
                string newName = GenerateRandomString();
                _renamedIdentifiers[originalName] = newName;
            }

            return node.WithIdentifier(SyntaxFactory.Identifier(_renamedIdentifiers[originalName]));
        }

        public override SyntaxNode VisitPropertyDeclaration(PropertyDeclarationSyntax node)
        {
            string originalName = node.Identifier.Text;
            if (!_renamedIdentifiers.ContainsKey(originalName))
            {
                string newName = GenerateRandomString();
                _renamedIdentifiers[originalName] = newName;
            }

            return node.WithIdentifier(SyntaxFactory.Identifier(_renamedIdentifiers[originalName]));
        }

        public override SyntaxNode VisitLiteralExpression(LiteralExpressionSyntax node)
        {
            if (node.IsKind(SyntaxKind.StringLiteralExpression))
            {
                string originalValue = node.Token.ValueText;
                string encryptedValue = EncryptString(originalValue);
                return SyntaxFactory.LiteralExpression(SyntaxKind.StringLiteralExpression,
                    SyntaxFactory.Literal(encryptedValue));
            }

            return base.VisitLiteralExpression(node);
        }

        public override SyntaxNode VisitIfStatement(IfStatementSyntax node)
        {
            // Example control flow obfuscation: add a dummy if statement
            var dummyCondition = SyntaxFactory.ParseExpression("false");
            var dummyIfStatement = SyntaxFactory.IfStatement(dummyCondition, SyntaxFactory.Block());

            var newStatement = node.WithElse(SyntaxFactory.ElseClause(dummyIfStatement));
            return base.VisitIfStatement(newStatement);
        }

        private string GenerateRandomString()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            int length = _random.Next(8, 16);
            char[] stringChars = new char[length];

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[_random.Next(chars.Length)];
            }

            return new string(stringChars);
        }

        private string EncryptString(string plainText)
        {
            ICryptoTransform encryptor = _aes.CreateEncryptor(_aes.Key, _aes.IV);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                }
                return Convert.ToBase64String(ms.ToArray());
            }
        }
    }
}
