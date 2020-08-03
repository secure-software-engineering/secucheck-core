package de.fraunhofer.iem.secucheck.analysis.sample;

import java.io.File;

import de.fraunhofer.iem.secucheck.analysis.query.MethodImpl;

public class Main {

	public static void main(String[] args) {
		try {
			secucheckAnalysisByLibrary();
//			secucheckAnalysisByProcess();
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static void secucheckAnalysisByLibrary() {
//		List<?> elements = XMLHelper.deserializeList(getXmlAnalysisSpecs());
//		List<TaintFlow> flowQueries = filterType(elements, TaintFlow.class);
//		List<Flow> flows = filterType(elements, Flow.class);
//		List<String> canonicalClassNames = Arrays.asList(getClassesToAnalyze().split(";"));			
//		AnalysisResult result = SpottyTestingFramework.run(getSootClassPath(), canonicalClassNames, flowQueries, flows, null);
//		System.out.println("Issue count:" + result.getIssues().size());
	
		MethodImpl	source = getSourceMethod(), 
					sanitizer = getSanitizerMethod(), 
					propogator = getPropogatorMethod() , 
					sink = getSinkMethod();
		
		
	}
	
	private static void secucheckAnalysisByProcess() {
		
		
//		File javaFile = getJavaBinaryFile();
//		File analysisJarFile = getAnalysisJarFile();
//		
//		if (javaFile != null && analysisJarFile != null) {
//			ProcessBuilder builder = new ProcessBuilder()
//					.command(javaFile.toString(), "-jar", analysisJarFile.toString())
//					.redirectError(Redirect.INHERIT);
//			Process process = builder.start();
//			PrintWriter pw = new PrintWriter(process.getOutputStream());
//			pw.println(getSootClassPath());
//			pw.println(getClassesToAnalyze());
//			pw.println(getXmlAnalysisSpecs());
//			pw.flush();
//			BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
//			while (!process.waitFor(1000, TimeUnit.MILLISECONDS)) {
//				System.out.print(readInput(br));
//			}
//			System.out.print(readInput(br));
//		}		
	}
	
	private static MethodImpl getSourceMethod() {
		return null;
	}
	
	private static MethodImpl getSanitizerMethod() {
		return null;
	}
	
	private static MethodImpl getPropogatorMethod() {
		return null;
	}
	
	private static MethodImpl getSinkMethod() {
		return null;
	}
	
	    // Use ';' for Windows and ':' for Linux or Mac.
//		private static String pathSeparator= ";";
//		private static String getSootClassPath() {
//			return 	System.getProperty("java.home") + File.separator + "lib" + File.separator +"rt.jar" + 
//					pathSeparator +
//					System.getProperty("user.dir") + File.separator +"bin";
//		}
			
//		private static String getClassesToAnalyze() {
//			return "Test;";
//		}
		
//		private static String getXmlAnalysisSpecs() {
//			return "<xmi:XMI xmi:version=\"2.0\" xmlns:xmi=\"http://www.omg.org/XMI\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:query=\"http://iem.fraunhofer.de/secucheck/query\">   <query:TaintFlow reportMessage=\"Invalid Information Flow\">     <partialTaintFlows from=\"/3\" notThrough=\"/2\" to=\"/1\"/>   </query:TaintFlow>   <query:Method name=\"m2\" signature=\"Test: void publish(int)\">     <inputDeclaration>       <inputs xsi:type=\"query:Parameter\"/>     </inputDeclaration>   </query:Method>   <query:Method name=\"s1\" signature=\"Test: int sanatizer(int)\"/>   <query:Method name=\"m1\" signature=\"Test: int getSecret()\">     <outputDeclaration>       <outputs xsi:type=\"query:ReturnValue\"/>     </outputDeclaration>   </query:Method> </xmi:XMI> ";
//		}
		
//		private static File getAnalysisJarFile() throws IOException {
//			return provideResource("/de.fraunhofer.iem.secucheck.analysis-0.0.1-SNAPSHOT-jar-with-dependencies.jar");
//		}
		
//		private static File provideResource(String resourcePath) throws IOException {
//			InputStream is = (InputStream) SecuCheckAnalysis.class.getResourceAsStream(resourcePath);
//			File file = File.createTempFile("SecuCheck", resourcePath.replace('/', '-'));
//			FileUtils.copyInputStreamToFile(is, file);
//			file.deleteOnExit();
//			return file;
//		}
		
//		private static File getJavaBinaryFile() {
//			File javaHome = new File(System.getProperty("java.home"));
//			File javaFiles[] = new File[] { new File(javaHome, "/bin/java.exe"), new File(javaHome, "/bin/java") };
//			for (File javaFile : javaFiles) {
//				if (javaFile.exists()) {
//					return javaFile;
//				}
//			}
//			return null;
//		}
		
//		@SuppressWarnings("unchecked")
//		private static <T> List<T> filterType(List<? extends Object> list, Class<T> type) {
//			List<T> result = new BasicEList<T>();
//			for (Object element : list) {
//				if (type.isInstance(element)) {
//					result.add((T) element);
//				}
//			}
//			return result;
//		}
		
//		private static String readInput(BufferedReader br) throws IOException {
//			String input = "";
//			while (br.ready()) {
//				try {
//					String line = null;
//					if ((line = br.readLine())== null) break; 
//						input += line;
//				} catch (IOException e) {
//					e.printStackTrace();
//					break;
//				}
//			}
//			return input;
//		}
}
