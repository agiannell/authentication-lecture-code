import axios from 'axios';
import React from 'react';
import {connect} from 'react-redux';
import {clearUser} from '../redux/reducer';

// componentDidMount() {
//     if(!this.props.user.email) {
//         this.props.history.push('/')
//     }
// }

const Dashboard = props => {
    // console.log(props)

    const logout = () => {
        axios.get('/api/logout')
            .then(() => {
                // Clear user information from redux state
                props.clearUser();

                // Navigate the user back to the auth page
                props.history.push('/');
            })
            .catch(err => console.log(err));
    }

    return (
        <main className='dashboard'>
            <section className='user-info'>
                <h3>{props.user.email}</h3>
                <button onClick={logout}>Log Out</button>
            </section>
        </main>
    )
}

const mapStateToProps = reduxState => reduxState;

export default connect(mapStateToProps, {clearUser})(Dashboard);