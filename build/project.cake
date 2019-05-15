public static class MyProject
{
    public static string RepositoryOwner { get; private set;} = "TheMoFaDe";
    public static string RepositoryName { get; private set;} = "DotNetHelper-Encryption";
    public static string SolutionDir  { get; private set;} = "./";
    public static string ProjectDir   { get; private set;} = "./src/DotNetHelper-Encryption/";
    public static string ProjectName  { get; private set;} = "DotNetHelper-Encryption"; 
    public static string SolutionFileName { get; private set;} = "DotNetHelper-Encryption.sln"; 
	public static string Manufacturer { get; private set;} = $"JosephMcNealJr";
    public static List<string> TargetFrameworks { get; } = new List<string>(){ "netstandard2.0" ,"net452", "net45" };
}