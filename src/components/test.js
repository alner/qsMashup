//import React, {Component} from 'react'
import { DragDropContext } from 'react-dnd';
import HTML5Backend from 'react-dnd-html5-backend';
import Component from './base';
import DragItem from './dragItem';

class TestDrag extends Component {
  constructor(props) {
    super(props)
  }

  componentDidMount() {
  }

  render() {
    return (
      <div style={{width: "100%", height: "100%", overflow: "auto"}}>
        <DragItem>
          {this.props.children}
        </DragItem>
      </div>
    )
  }
}

//export default DragDropContext(HTML5Backend)(TestDrag);
export default TestDrag;
