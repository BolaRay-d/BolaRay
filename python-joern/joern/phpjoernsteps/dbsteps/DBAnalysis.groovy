import java.io.*;
import java.util.*;

class DBAnalysis {

    String appName;

    String sqlStatementsFilePath;
    ArrayList<ColDef> allColDefinSchema;

    DBAnalysis(String appName, String sqlStatementsFilePath) {
        this.appName = appName;
        this.sqlStatementsFilePath = sqlStatementsFilePath;
        this.allColDefinSchema = new ArrayList<ColDef>();
    }

    String getAppName() {
        return appName;
    }

    void setAppName(String appName) {
        this.appName = appName;
    }

    ArrayList<ColDef> getAllColDefinSchema() {
        return allColDefinSchema;
    }

    void setAllColDefinSchema(ArrayList<ColDef> allColDefinSchema) {
        this.allColDefinSchema = allColDefinSchema;
    }

    //For testing and generating the parsed schema in csv formate
    void parse() {

        File sqlStatementsFile = new File(sqlStatementsFilePath);

        try {
            Scanner scanner = new Scanner(sqlStatementsFile);

            while (scanner.hasNextLine()) {
                String line = scanner.nextLine();
                QueryProcessing.ParseQuery(line);
            }
            scanner.close();
        } catch (FileNotFoundException e) {
            System.err.println("File not found: " + sqlStatementsFilePath);
        }
    }
}