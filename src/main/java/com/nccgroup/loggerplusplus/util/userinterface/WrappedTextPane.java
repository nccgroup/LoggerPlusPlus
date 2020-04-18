package com.nccgroup.loggerplusplus.util.userinterface;

import javax.swing.*;
import javax.swing.text.*;

public class WrappedTextPane extends JTextPane {

    public WrappedTextPane(StyledDocument styledDocument){
        this.setEditorKit(new WrapEditorKit());
    }

    public WrappedTextPane(){
        this.setEditorKit(new WrapEditorKit());
    }

    class WrapEditorKit extends StyledEditorKit {
        ViewFactory factory = new WrapColumnFactory();
        public ViewFactory getViewFactory() {
            return factory;
        }
    }

    class WrapColumnFactory implements ViewFactory {
        public View create(Element elem) {
            String kind = elem.getName();
            if (kind != null) {
                if (kind.equals(AbstractDocument.ContentElementName)) {
                    return new WrapLabelView(elem);
                } else if (kind.equals(AbstractDocument.ParagraphElementName)) {
                    return new ParagraphView(elem);
                } else if (kind.equals(AbstractDocument.SectionElementName)) {
                    return new BoxView(elem, View.Y_AXIS);
                } else if (kind.equals(StyleConstants.ComponentElementName)) {
                    return new ComponentView(elem);
                } else if (kind.equals(StyleConstants.IconElementName)) {
                    return new IconView(elem);
                }
            }

            // default to text display
            return new LabelView(elem);
        }
    }

    class WrapLabelView extends LabelView {
        public WrapLabelView(Element elem) {
            super(elem);
        }

        public float getMinimumSpan(int axis) {
            switch (axis) {
                case View.X_AXIS:
                    return 0;
                case View.Y_AXIS:
                    return super.getMinimumSpan(axis);
                default:
                    throw new IllegalArgumentException("Invalid axis: " + axis);
            }
        }

    }
}
