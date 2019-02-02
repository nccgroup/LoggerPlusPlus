package loggerplusplus.userinterface;

import org.jdesktop.swingx.JXTableHeader;

import javax.swing.*;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

// This was used to create tool tips
public class TableHeader extends JTableHeader {

	private final LogTableColumnModel tableColumnModel;
	
	TableHeader(TableColumnModel tcm, final LogTable logTable) {
		super(tcm);
		this.tableColumnModel = (LogTableColumnModel) tcm;
		this.setTable(logTable);

		this.addMouseListener(new MouseAdapter(){
			@Override
			public void mouseReleased(MouseEvent e)
			{
				if ( SwingUtilities.isRightMouseButton( e ))
				{
					// get the coordinates of the mouse click
					Point p = e.getPoint();
					int columnID = logTable.convertColumnIndexToModel(columnAtPoint(p));
					LogTableColumn column = (LogTableColumn) tableColumnModel.getColumn(columnID);
					//TODO
					TableHeaderMenu tblHeaderMenu = new TableHeaderMenu(logTable, column);
					tblHeaderMenu.showMenu(e);
				}else if(SwingUtilities.isLeftMouseButton(e)){

				}
			}
		});

	}

	@Override
	public String getToolTipText(MouseEvent e) {

		// get the coordinates of the mouse click
		Point p = e.getPoint();
		int columnID = TableHeader.this.getTable().convertColumnIndexToModel(TableHeader.this.getTable().columnAtPoint(p));
		LogTableColumn column = (LogTableColumn) TableHeader.this.getTable().getColumnModel().getColumn(columnID);

		String retStr;
		try {
			retStr = column.getDescription();
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
