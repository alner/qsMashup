import Component from './base';

class DragItem extends Component {
  componentDidMount(){
    // if IsEditMode
    $('.draggable').draggable();
    $('.draggable').resizable();

    // else if($(r).children().draggable("instance")) $(r).children().draggable("destroy");
  }
  render(){
    /*
    <div className="ui-resizable-handle ui-resizable-e" style={{zIndex: 90}}></div>
    <div className="ui-resizable-handle ui-resizable-s" style={{zIndex: 90}}></div>
    <div className="ui-resizable-handle ui-resizable-se ui-icon ui-icon-gripsmall-diagonal-se" style={{zIndex: 90}}>
    </div>
    */
    return (
    <div className="draggable" style={{background: "green", width: "200px", height: "200px"}} >
      {this.props.children}
    </div>
    );
  }
}

export default DragItem;
