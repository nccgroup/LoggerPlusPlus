package burp;

import java.awt.Point;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import burp.BurpExtender.Table;
import burp.BurpExtender.TableHelper;

// This was used to create tool tips
public class TableHeader extends JTableHeader {

	private final Table logTable;
	private final TableHelper tableHelper;
	private final boolean isDebug;
	private final PrintWriter stdout, stderr;
	
	TableHeader(TableColumnModel tcm, Table logTable, TableHelper tableHelper, PrintWriter stdout, PrintWriter stderr, boolean isDebug) {
		super(tcm);
		this.logTable = logTable;
		this.tableHelper= tableHelper;
		this.isDebug=isDebug;
		this.stdout = stdout;
		this.stderr=stderr;
	}

	@Override
	public String getToolTipText(MouseEvent e) {

		// get the coordinates of the mouse click
		Point p = e.getPoint();
		int columnID = logTable.columnAtPoint(p);
		TableColumn column = logTable.getColumnModel().getColumn(columnID);
		TableStructure columnObj = tableHelper.getTableHeaderColumnsDetails().getAllColumnsDefinitionList().get((Integer) column.getIdentifier());
		if(isDebug){
			stdout.println("right click detected on the header!");
			stdout.println("right click on item number " + String.valueOf(columnID) + " ("+logTable.getColumnName(columnID)+") was detected");
		}

		String retStr;
		try {
			retStr = columnObj.getDescription();
		} catch (NullPointerException ex) {
			retStr = "";
		} catch (ArrayIndexOutOfBoundsException ex) {
			retStr = "";
		}
		if (retStr.length() < 1) {
			retStr = super.getToolTipText(e);
		}
		return retStr;

	}
}
