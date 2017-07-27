package burp;

import javax.swing.*;
import javax.swing.event.TableColumnModelEvent;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;

// This was used to create tool tips
public class TableHeader extends JTableHeader {

	private final LogTableColumnModel tableColumnModel;
	private final LogTable logTable;
	private final boolean isDebug;
	private final PrintWriter stdout, stderr;
	
	TableHeader(TableColumnModel tcm, final LogTable logTable, PrintWriter stdout, PrintWriter stderr, boolean isDebug) {
		super(tcm);
		this.tableColumnModel = (LogTableColumnModel) tcm;
		this.logTable = logTable;
		this.isDebug=isDebug;
		this.stdout = stdout;
		this.stderr=stderr;

		this.addMouseListener(new MouseAdapter(){
			@Override
			public void mouseReleased(MouseEvent e)
			{
				if ( SwingUtilities.isRightMouseButton( e ))
				{
					// get the coordinates of the mouse click
					Point p = e.getPoint();
					int columnID = columnAtPoint(p);
					LogTableColumn column = tableColumnModel.getColumn(columnID);
					//TODO
					TableHeaderMenu tblHeaderMenu = new TableHeaderMenu(logTable, column);
					tblHeaderMenu.showMenu(e);
				}else if(SwingUtilities.isLeftMouseButton(e)){

				}


//				if(isColumnWidthChanged()){
//					/* On mouse release, check if column width has changed */
//					if(isDebug) {
//						stdout.println("Column has been resized!");
//					}
//
//					// Reset the flag on the table.
//					setColumnWidthChanged(false);
//
//					saveColumnResizeTableChange();
//				}else if(isColumnMoved()){
//						/* On mouse release, check if column has moved */
//
//					if(isDebug) {
//						stdout.println("Column has been moved!");
//					}
//					// Reset the flag on the table.
//					setColumnMoved(false);
//					saveOrderTableChange();
//				}
			}
		});

	}

	@Override
	public String getToolTipText(MouseEvent e) {

		// get the coordinates of the mouse click
		Point p = e.getPoint();
		int columnID = logTable.columnAtPoint(p);
		LogTableColumn column = logTable.getColumnModel().getColumn(columnID);

		String retStr;
		try {
			retStr = column.getDescription();
		} catch (NullPointerException | ArrayIndexOutOfBoundsException ex) {
			retStr = "";
		}
		if (retStr.length() < 1) {
			retStr = super.getToolTipText(e);
		}
		return retStr;

	}

	@Override
	public void columnAdded(TableColumnModelEvent var1) {
		this.resizeAndRepaint();
	}

	public void columnRemoved(TableColumnModelEvent var1) {
		this.resizeAndRepaint();
	}

	@Override
	public void columnMoved(TableColumnModelEvent var1) {
		this.resizeAndRepaint();
	}
}
