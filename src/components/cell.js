import Component from './base';
import senseDragDropSupport from '../utils/senseDragDropSupport';

class Cell extends Component {
  displayName: 'Cell'
  render() {
    if(this.props.item) console.log('Cell', this.props.item);
    return <div className='markup-cell'>Cell!</div>;
  }
}

// placeClassName - where an sense object will be injected
export default senseDragDropSupport({placeClassName: 'markup-cell'})(Cell);
