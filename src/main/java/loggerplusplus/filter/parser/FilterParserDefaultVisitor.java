/* Generated By:JavaCC: Do not edit this line. FilterParserDefaultVisitor.java Version 7.0.2 */
package loggerplusplus.filter.parser;

public class FilterParserDefaultVisitor implements FilterParserVisitor{
  public Object defaultVisit(SimpleNode node, Object data){
    node.childrenAccept(this, data);
    return data;
  }
  public Object visit(SimpleNode node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTExpression node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTComparison node, Object data){
    return defaultVisit(node, data);
  }
  public Object visit(ASTSimpleBoolean node, Object data){
    return defaultVisit(node, data);
  }
}
/* JavaCC - OriginalChecksum=0619b803ceb5f5e767fcd30c14008037 (do not edit this line) */
