package com.nccgroup.loggerplusplus.logview.logtable;

import javax.swing.*;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

// This was used to create tool tips
public class TableHeader extends JTableHeader {

	
	TableHeader(LogTableController logTableController) {
		super(logTableController.getLogTableColumnModel());

		this.setTable(logTableController.getLogTable());

		this.addMouseListener(new MouseAdapter(){
			@Override
			public void mouseReleased(MouseEvent e)
			{
				if ( SwingUtilities.isRightMouseButton( e )){
					// get the coordinates of the mouse click
					Point p = e.getPoint();
					int columnIndex = columnAtPoint(p);
					LogTableColumn column = (LogTableColumn) getColumnModel().getColumn(columnIndex);

					TableHeaderMenu tblHeaderMenu = new TableHeaderMenu(logTableController, column);
					tblHeaderMenu.showMenu(e);
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
		} catch (NullPointerException | ArrayIndexOutOfBoundsException ex) {
			retStr = "";
		}
		if (retStr.length() < 1) {
			retStr = super.getToolTipText(e);
		}
		return retStr;

	}
}
